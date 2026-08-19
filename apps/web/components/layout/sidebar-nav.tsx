"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { cn } from "@/lib/utils";

const items = [
  {
    href: "/",
    label: "Dashboard",
    description: "Lab-wide operating view",
    glyph: "01",
  },
  {
    href: "/phantom",
    label: "Phantom",
    description: "Lookalike-domain detection",
    glyph: "02",
  },
  {
    href: "/programs",
    label: "Recon Programs",
    description: "Scope, targets, hypotheses",
    glyph: "03",
  },
  {
    href: "/approvals",
    label: "Approval Queue",
    description: "Human decision lane",
    glyph: "04",
  },
  {
    href: "/monitor",
    label: "Monitor",
    description: "Live CT-stream matches",
    glyph: "05",
  },
];

export function SidebarNav({ mobile = false }: { mobile?: boolean }) {
  const pathname = usePathname();

  return (
    <nav className={cn("flex gap-3", mobile ? "overflow-x-auto pb-2" : "flex-col")}>
      {items.map((item) => {
        const active =
          item.href === "/"
            ? pathname === item.href
            : pathname === item.href || pathname.startsWith(`${item.href}/`);

        return (
          <Link
            key={item.href}
            href={item.href}
            className={cn(
              "group flex shrink-0 items-start gap-4 rounded-[22px] border px-4 py-4 transition-colors",
              active
                ? "border-[var(--border-accent)] bg-[var(--surface-selected)]"
                : "border-transparent bg-transparent hover:border-[var(--border-subtle)] hover:bg-white/[0.04]",
            )}
          >
            <div
              className={cn(
                "flex h-10 w-10 items-center justify-center rounded-2xl text-xs font-bold tracking-[0.2em]",
                active
                  ? "bg-[var(--accent)] text-[var(--accent-foreground)]"
                  : "border border-[var(--border-subtle)] bg-white/[0.045] text-white/75",
              )}
            >
              {item.glyph}
            </div>
            <div className="min-w-0">
              <div className="text-sm font-semibold text-[var(--foreground-strong)]">{item.label}</div>
              <div className="mt-1 text-xs leading-5 text-[var(--muted-foreground)]">{item.description}</div>
            </div>
          </Link>
        );
      })}
    </nav>
  );
}
