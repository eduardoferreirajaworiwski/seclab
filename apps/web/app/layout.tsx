import type { Metadata } from "next";

import "@/app/globals.css";
import { AppShell } from "@/components/layout/app-shell";
import { AppProviders } from "@/components/providers/app-providers";

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
    <html lang="en">
      <body>
        <AppProviders>
          <AppShell>{children}</AppShell>
        </AppProviders>
      </body>
    </html>
  );
}
