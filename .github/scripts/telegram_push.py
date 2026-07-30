#!/usr/bin/env python3
"""
Polls a Telegram bot for new messages in a specific group, looks for
"/push <domain>" commands from an allow-listed set of Telegram user IDs,
validates + normalizes the domain, and appends it to
data/investment-fraud-domains.json if it isn't already there. Who added
what is only visible in the git commit history and the bot's chat replies,
not in a separate file.

State (last processed Telegram update_id) is kept in
.github/telegram-offset.json so re-runs never reprocess old messages.

Required environment variables:
  TELEGRAM_BOT_TOKEN        - bot token from @BotFather
  TELEGRAM_CHAT_ID          - the group's chat id (negative number for groups)
  TELEGRAM_ALLOWED_USER_IDS - comma-separated Telegram numeric user ids allowed to /push

Exit code is always 0 on a handled run (errors are logged, not raised) so a
single bad message can't fail the whole workflow. Malformed *code* errors do
raise, since those should fail loudly in CI.
"""
import json
import os
import re
import sys
import urllib.request
import urllib.error

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
DOMAINS_PATH = os.path.join(REPO_ROOT, "data", "investment-fraud-domains.json")
OFFSET_PATH = os.path.join(REPO_ROOT, ".github", "telegram-offset.json")

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "")
ALLOWED_USER_IDS = {
    uid.strip() for uid in os.environ.get("TELEGRAM_ALLOWED_USER_IDS", "").split(",") if uid.strip()
}

API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}"

# Basic domain shape check: labels of 1-63 chars, letters/digits/hyphen,
# no leading/trailing hyphen, at least one dot (a real registrable domain).
DOMAIN_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))+$"
)

HELP_TEXT = (
    "🤖 Как да добавям домейни:\n\n"
    "/push домейн.com — добавя домейн в списъка с измамни домейни на сайта.\n"
    "Може да пратиш и цял линк (https://домейн.com/страница) — ботът сам изчиства до голия домейн.\n\n"
    "Примери:\n"
    "/push evil-scam.com\n"
    "/push https://fake-broker.io/login\n\n"
    "Само одобрени потребители могат да добавят домейни. Ако нямаш права, обърни се към администратор на групата.\n\n"
    "Домейнът се появява на сайта до няколко минути след /push (не веднага)."
)


def api_call(method, params=None):
    url = f"{API_BASE}/{method}"
    data = json.dumps(params or {}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return json.load(resp)
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", errors="replace")
        print(f"::warning::Telegram API error calling {method}: HTTP {e.code} - {body}")
        return {"ok": False, "error_code": e.code, "description": body}


def load_offset():
    if os.path.exists(OFFSET_PATH):
        with open(OFFSET_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("last_update_id", 0)
    return 0


def save_offset(update_id):
    os.makedirs(os.path.dirname(OFFSET_PATH), exist_ok=True)
    with open(OFFSET_PATH, "w", encoding="utf-8") as f:
        json.dump({"last_update_id": update_id}, f, indent=2)
        f.write("\n")


def load_domains():
    if os.path.exists(DOMAINS_PATH):
        with open(DOMAINS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    return []


def save_domains(domains):
    with open(DOMAINS_PATH, "w", encoding="utf-8") as f:
        json.dump(domains, f, ensure_ascii=False, indent=4)
        f.write("\n")


def normalize_domain(raw):
    """Strip scheme/path/query, lowercase, IDN-encode to punycode.
    Returns the normalized domain string, or None if it isn't a valid domain."""
    raw = raw.strip()
    # Strip a scheme if present, and any path/query/fragment.
    raw = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", raw)
    raw = raw.split("/")[0]
    raw = raw.split("?")[0]
    raw = raw.split("#")[0]
    raw = raw.split(":")[0]  # drop a port if present
    raw = raw.strip().strip(".").lower()

    if not raw:
        return None

    # IDN -> punycode per-label (catches homograph lookalikes at storage time).
    try:
        labels = raw.split(".")
        encoded_labels = [label.encode("idna").decode("ascii") for label in labels]
        normalized = ".".join(encoded_labels)
    except UnicodeError:
        return None

    if not DOMAIN_RE.match(normalized):
        return None

    return normalized


def reply(chat_id, text, reply_to_message_id=None):
    params = {"chat_id": chat_id, "text": text}
    if reply_to_message_id:
        params["reply_to_message_id"] = reply_to_message_id
    try:
        api_call("sendMessage", params)
    except Exception as e:  # noqa: BLE001 - a failed reply must never fail the run
        print(f"::warning::Failed to send Telegram reply: {e}")


def main():
    if not BOT_TOKEN:
        print("::error::TELEGRAM_BOT_TOKEN is not set")
        sys.exit(1)
    if not CHAT_ID:
        print("::error::TELEGRAM_CHAT_ID is not set")
        sys.exit(1)
    if not ALLOWED_USER_IDS:
        print("::error::TELEGRAM_ALLOWED_USER_IDS is not set (refusing to run with an empty allowlist)")
        sys.exit(1)

    offset = load_offset()
    updates = api_call("getUpdates", {"offset": offset + 1, "timeout": 0})

    if not updates.get("ok"):
        print(f"::error::getUpdates failed: {updates}")
        sys.exit(1)

    domains = load_domains()
    existing = set(domains)
    changed = False
    max_update_id = offset

    for update in updates["result"]:
        max_update_id = max(max_update_id, update["update_id"])
        message = update.get("message") or update.get("edited_message")
        if not message:
            continue

        text = (message.get("text") or "").strip()
        text_lower = text.lower()
        is_push = text_lower.startswith("/push")
        is_help = text_lower.startswith("/help") or text_lower.startswith("/start")
        if not (is_push or is_help):
            continue

        chat_id = str(message.get("chat", {}).get("id", ""))
        user = message.get("from", {})
        user_id = str(user.get("id", ""))
        username = user.get("username") or user.get("first_name") or user_id
        message_id = message.get("message_id")

        if chat_id != str(CHAT_ID):
            continue  # command from a different chat entirely, ignore silently

        if is_help:
            # Anyone in the group can ask for help, regardless of allowlist.
            reply(chat_id, HELP_TEXT, message_id)
            continue

        if user_id not in ALLOWED_USER_IDS:
            print(f"Ignoring /push from non-allowlisted user {user_id} ({username})")
            reply(chat_id, "⛔️ Нямаш права да добавяш домейни. Пробвай /help за повече информация.", message_id)
            continue

        parts = text.split(maxsplit=1)
        if len(parts) < 2 or not parts[1].strip():
            reply(chat_id, "Употреба: /push домейн.com", message_id)
            continue

        domain = normalize_domain(parts[1])
        if domain is None:
            reply(chat_id, f"❌ Невалиден домейн: {parts[1].strip()}", message_id)
            continue

        if domain in existing:
            reply(chat_id, f"ℹ️ {domain} вече е в списъка.", message_id)
            continue

        domains.insert(0, domain)
        existing.add(domain)
        changed = True

        reply(chat_id, f"✅ Добавен: {domain}", message_id)
        print(f"Added domain: {domain} (by {username}/{user_id})")

    if changed:
        save_domains(domains)

    if max_update_id != offset:
        save_offset(max_update_id)

    # Signal to the workflow whether there's anything to commit.
    gh_output = os.environ.get("GITHUB_OUTPUT")
    if gh_output:
        with open(gh_output, "a", encoding="utf-8") as f:
            f.write(f"changed={'true' if changed else 'false'}\n")


if __name__ == "__main__":
    main()
