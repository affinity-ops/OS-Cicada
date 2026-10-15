// © 2026 Affinity Ops Ltd. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

import type { Config } from "tailwindcss";

const config: Config = {
  content: [
    "./src/pages/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/components/**/*.{js,ts,jsx,tsx,mdx}",
    "./src/app/**/*.{js,ts,jsx,tsx,mdx}",
  ],
  theme: {
    extend: {
      colors: {
        primary: "#ff9f4a",
        "primary-dark": "#fd8b00",
        secondary: "#f9c13d",
        background: "#0a0a0a",
        surface: "#111111",
        "surface-raised": "#181818",
        "on-surface": "#ffffff",
        "on-surface-muted": "#888888",
        border: "rgba(255, 159, 74, 0.12)",
      },
      fontFamily: {
        headline: ["Space Grotesk", "sans-serif"],
        body: ["Manrope", "sans-serif"],
        technical: ["JetBrains Mono", "monospace"],
      },
    },
  },
  plugins: [],
};
export default config;
