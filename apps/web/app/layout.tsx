import type { Metadata } from "next";
import { Inter, JetBrains_Mono } from "next/font/google";

import "@/app/globals.css";
import { AppShell } from "@/components/layout/app-shell";
import { AppProviders } from "@/components/providers/app-providers";

const inter = Inter({ subsets: ["latin"], variable: "--font-sans" });
const jetbrainsMono = JetBrains_Mono({ subsets: ["latin"], variable: "--font-mono" });

export const metadata: Metadata = {
  title: "SecLab | Personal security laboratory",
  description:
    "Unified operator console for the seclab modules: lookalike-domain detection, human-in-the-loop bug bounty workflow, and real-time CT monitoring.",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className={`${inter.variable} ${jetbrainsMono.variable}`}>
      <body>
        <AppProviders>
          <AppShell>{children}</AppShell>
        </AppProviders>
      </body>
    </html>
  );
}
