/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        surface: {
          root: 'var(--color-surface-root)',
          sidebar: 'var(--color-surface-sidebar)',
          card: 'var(--color-surface-card)',
          elevated: 'var(--color-surface-elevated)',
          hover: 'var(--color-surface-hover)',
        },
        border: {
          subtle: 'var(--color-border-subtle)',
          muted: 'var(--color-border-muted)',
          light: 'var(--color-border-light)',
          main: 'var(--color-border-subtle)',
        },
        text: {
          primary: 'var(--color-text-primary)',
          secondary: 'var(--color-text-secondary)',
          muted: 'var(--color-text-muted)',
        },
        accent: {
          blue: 'var(--color-accent-blue)',
        },
        nbx: {
          DEFAULT: '#3B82F6',
          dark: '#1D4ED8',
          light: '#60A5FA',
          bg: '#172554',
        },
        hp: {
          DEFAULT: '#8B5CF6',
          dark: '#6D28D9',
          light: '#A78BFA',
          bg: '#2E1065',
        },
        soc: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#F59E0B',
          low: '#10B981',
          info: '#64748B',
        }
      },
    },
  },
  plugins: [],
}

