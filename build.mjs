// build.mjs
// Precompiles JSX -> plain JS at build time (instead of shipping Babel Standalone
// and transpiling in the browser). This lets us drop 'unsafe-eval' and
// 'unsafe-inline' from script-src in the Content-Security-Policy.
//
// Usage: node build.mjs
import * as esbuild from 'esbuild';
import { execSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const entries = [
  { in: 'src/index.jsx', out: 'assets/js/dist/index.bundle.js' },
  { in: 'src/investment-fraud.jsx', out: 'assets/js/dist/investment-fraud.bundle.js' },
];

// We keep using the already-vetted, self-hosted esm.sh builds of React /
// ReactDOM / lucide-react instead of pulling fresh copies from npm. This
// avoids introducing a new supply-chain surface and keeps the bundle
// byte-for-byte traceable to what was manually reviewed.
const alias = {
  react: path.resolve(__dirname, 'assets/js/react.js'),
  'react-dom/client': path.resolve(__dirname, 'assets/js/react-dom.js'),
  'lucide-react': path.resolve(__dirname, 'assets/js/lucide-react.js'),
};

for (const entry of entries) {
  await esbuild.build({
    entryPoints: [entry.in],
    outfile: entry.out,
    bundle: true,
    minify: true,
    sourcemap: false,
    format: 'iife',
    target: ['es2019'],
    // Classic transform (React.createElement) because the vendored
    // esm.sh React build doesn't expose a react/jsx-runtime entry point.
    jsx: 'transform',
    jsxFactory: 'React.createElement',
    jsxFragment: 'React.Fragment',
    loader: { '.jsx': 'jsx' },
    alias,
    legalComments: 'none',
    logLevel: 'info',
  });
  console.log(`built ${entry.in} -> ${entry.out}`);
}

// Precompile Tailwind CSS (replaces the runtime tailwindcss.js "play CDN"
// build, which injects <style> tags at runtime and therefore requires
// style-src 'unsafe-inline'). The static build only ships the CSS classes
// actually used in src/*.jsx and *.html, and is a fraction of the size.
execSync(
  'npx tailwindcss -i ./src/tailwind.css -o ./assets/css/tailwind.min.css --minify',
  { stdio: 'inherit' }
);

console.log('Build complete.');
