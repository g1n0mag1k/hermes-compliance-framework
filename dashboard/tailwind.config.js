/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,jsx}"],
  theme: {
    extend: {
      colors: {
        navy: "var(--navy)",
        blue: "var(--blue)",
        verified: "var(--verified)",
        warning: "var(--warning)",
        critical: "var(--critical)",
        unknown: "var(--unknown)",
        canvas: "var(--canvas)",
      },
      fontFamily: {
        sans: ["Inter", "sans-serif"],
      },
    },
  },
  plugins: [],
};
