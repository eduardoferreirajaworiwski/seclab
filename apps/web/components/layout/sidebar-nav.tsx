"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";

import { cn } from "@/lib/utils";

const sections = [
  {
    label: null,
    items: [
      {
        href: "/",
        label: "Dashboard",
        description: "Lab-wide operating view",
        glyph: "01",
      },
      {
        href: "/docs",
        label: "Como funciona",
        description: "Arquitetura, módulos e autenticação explicados",
        glyph: "00",
      },
    ],
  },
  {
    label: "Recon & discovery",
    items: [
      {
        href: "/phantom",
        label: "Phantom",
        description: "Lookalike-domain detection",
        glyph: "02",
      },
      {
        href: "/programs",
        label: "Recon Programs",
        description: "Scope, targets, hypotheses, attack surface",
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
    ],
  },
  {
    label: "Threat intel",
    items: [
      {
        href: "/intel",
        label: "Intel",
        description: "News and CVE digests",
        glyph: "06",
      },
      {
        href: "/fusion",
        label: "Fusion",
        description: "Cross-module correlation feed",
        glyph: "07",
      },
    ],
  },
];

export function SidebarNav({ mobile = false }: { mobile?: boolean }) {
  const pathname = usePathname();

  if (mobile) {
    return (
      <nav className="flex gap-3 overflow-x-auto pb-2">
        {sections.flatMap((section) => section.items).map((item) => (
          <NavLink key={item.href} item={item} pathname={pathname} mobile />
        ))}
      </nav>
    );
  }

  return (
    <nav className="flex flex-col gap-6">
      {sections.map((section, index) => (
        <div key={section.label ?? `section-${index}`} className="flex flex-col gap-2">
          {section.label ? (
            <p className="px-1 text-[10px] font-semibold uppercase tracking-[0.16em] text-[var(--subtle-foreground)]">
              {section.label}
            </p>
          ) : null}
          <div className="flex flex-col gap-2">
            {section.items.map((item) => (
              <NavLink key={item.href} item={item} pathname={pathname} />
            ))}
          </div>
        </div>
      ))}
    </nav>
  );
}

function NavLink({
  item,
  pathname,
  mobile = false,
}: {
  item: { href: string; label: string; description: string; glyph: string };
  pathname: string;
  mobile?: boolean;
}) {
  const active =
    item.href === "/" ? pathname === item.href : pathname === item.href || pathname.startsWith(`${item.href}/`);

  return (
    <Link
      href={item.href}
      className={cn(
        "group flex shrink-0 items-start gap-4 rounded-lg border px-4 py-4 transition-colors",
        mobile ? "min-w-[220px]" : "",
        active
          ? "border-[var(--border-accent)] bg-[var(--surface-selected)]"
          : "border-transparent bg-transparent hover:border-[var(--border-subtle)] hover:bg-[var(--surface-hover)]",
      )}
    >
      <div
        className={cn(
          "flex h-10 w-10 items-center justify-center rounded-md text-xs font-bold tracking-[0.2em]",
          active
            ? "bg-[var(--accent)] text-[var(--accent-foreground)]"
            : "border border-[var(--border-subtle)] bg-[var(--surface-inset)] text-[var(--muted-foreground)]",
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
}
