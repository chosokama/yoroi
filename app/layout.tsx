import type { Metadata } from "next";
import { Barlow, Barlow_Condensed } from "next/font/google";
import { Providers } from "@/components/providers";
import "./globals.css";

const barlow = Barlow({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
  variable: "--font-barlow",
  display: "swap",
});

const barlowCondensed = Barlow_Condensed({
  subsets: ["latin"],
  weight: ["600", "700", "800", "900"],
  variable: "--font-barlow-condensed",
  display: "swap",
});

export const metadata: Metadata = {
  title: "MoltWall - AI Agent Security Firewall",
  description:
    "Production-grade security firewall for AI agents. Evaluate, control, and audit every agent action before execution.",
  keywords: ["AI security", "agent firewall", "MCP", "tool safety", "prompt injection", "MoltWall"],
  metadataBase: new URL("https://www.moltwall.xyz"),
  icons: {
    icon: "/icon.png",
    apple: "/icon.png",
  },
};

export default function RootLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return (
    <html lang="en" className={`${barlow.variable} ${barlowCondensed.variable}`}>
      <body className="antialiased">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
