/** @type {import('tailwindcss').Config} */
export default {
  // Scan the JSX sources (pre-bundle) and the HTML shells for class names.
  content: ['./src/**/*.{jsx,js,html}', './*.html'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Montserrat', 'ui-sans-serif', 'system-ui', 'sans-serif'],
      },
      colors: {
        'gdbop-blue': '#47a8f6',
        'gdbop-dark': '#0f172a', // slate-900
        'police-blue': '#0055ff',
        'police-red': '#ff0000',
      },
      animation: {
        'pulse-slow': 'pulse 4s cubic-bezier(0.4, 0, 0.6, 1) infinite',
        float: 'float 6s ease-in-out infinite',
        scan: 'scan 4s linear infinite',
      },
      keyframes: {
        float: {
          '0%, 100%': { transform: 'translateY(0)' },
          '50%': { transform: 'translateY(-10px)' },
        },
        scan: {
          '0%': { top: '-10%' },
          '100%': { top: '110%' },
        },
      },
    },
  },
  plugins: [],
};
