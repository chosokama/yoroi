import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./components/**/*.{js,ts,jsx,tsx,mdx}",
    "./app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        gold: "#FFC400",
        "gold-dim": "#CC9D00",
      },
      fontFamily: {
        sans: ["var(--font-barlow)", "ui-sans-serif", "system-ui", "sans-serif"],
        display: ["var(--font-barlow-condensed)", "var(--font-barlow)", "sans-serif"],
        mono: ["ui-monospace", "SFMono-Regular", "monospace"],
      },
      fontSize: {
        "hero-sm": ["2.5rem", { lineHeight: "1", fontWeight: "800", letterSpacing: "-0.01em" }],
        "hero":    ["3.5rem", { lineHeight: "1", fontWeight: "800", letterSpacing: "-0.01em" }],
        "hero-lg": ["4.5rem", { lineHeight: "1", fontWeight: "900", letterSpacing: "-0.02em" }],
      },
    },
  },
  plugins: [],
};

export default config;
