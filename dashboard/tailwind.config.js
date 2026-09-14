/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,jsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy:     '#12263A',
        blue:     '#2563EB',
        verified: '#14866D',
        warning:  '#C47A00',
        critical: '#C43D4D',
        unknown:  '#667085',
        canvas:   '#F7F9FC',
      },
      fontFamily: {
        sans: ['Inter', 'ui-sans-serif', 'system-ui'],
      },
    },
  },
  plugins: [],
}
