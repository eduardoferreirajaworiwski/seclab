"use client";

import { usePathname } from "next/navigation";

import { ApiKeyControl } from "@/components/layout/api-key-control";
import { StatusBadge } from "@/components/shared/status-badge";
import { useHealthQuery } from "@/lib/api/hooks";

const pageLabels: Record<string, string> = {
  "/": "Lab overview",
  "/docs": "Como funciona",
  "/onboarding": "Primeiros passos",
  "/phantom": "Lookalike-domain analysis",
  "/programs": "Recon program inventory",
  "/approvals": "Human approval workflow",
  "/monitor": "Certificate Transparency monitor",
  "/intel": "Threat intelligence digests",
  "/fusion": "Cross-module correlation feed",
};

export function Topbar() {
  const pathname = usePathname();
  const healthQuery = useHealthQuery();

  const section =
    pathname.startsWith("/programs/")
      ? "Program detail"
      : pageLabels[pathname] ?? "Operator workspace";

  const healthy = healthQuery.data?.status === "ok";

  return (
    <header className="panel-strong sticky top-4 z-20 px-5 py-4">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <p className="eyebrow">SecLab</p>
          <div className="mt-1 text-lg font-semibold tracking-[-0.02em] text-[var(--foreground-strong)]">{section}</div>
        </div>
        <div className="flex flex-wrap items-center gap-3">
          <StatusBadge
            status={healthy ? "approved" : "pending"}
            label={healthy ? "API Connected" : healthQuery.isPending ? "Checking API" : "API Unreachable"}
          />
          <div className="rounded-full border border-[var(--border-subtle)] bg-[var(--surface-inset)] px-4 py-2 text-[11px] font-semibold uppercase tracking-[0.16em] text-[var(--muted-foreground)]">
            Human-in-the-loop enforced
          </div>
          <ApiKeyControl />
        </div>
      </div>
    </header>
  );
}
