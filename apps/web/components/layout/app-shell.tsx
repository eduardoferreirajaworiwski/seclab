"use client";

import { SidebarNav } from "@/components/layout/sidebar-nav";
import { Topbar } from "@/components/layout/topbar";

export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <div className="mx-auto flex min-h-screen w-full max-w-[1700px] gap-6 px-4 py-4 md:px-6 lg:px-8">
      <aside className="hidden w-[290px] shrink-0 lg:block">
        <div className="panel-strong sticky top-4 flex h-[calc(100vh-2rem)] flex-col p-5">
          <div className="space-y-4 p-1">
            <div className="flex items-center gap-3">
              <div className="flex h-11 w-11 items-center justify-center rounded-md border border-[var(--border-accent)] bg-[var(--accent-soft)] text-sm font-bold tracking-[-0.04em] text-teal-100">
                SL
              </div>
              <div>
                <p className="eyebrow">SecLab</p>
                <div className="mt-1 text-2xl font-semibold tracking-[-0.04em] text-[var(--foreground-strong)]">
                  Console
                </div>
              </div>
            </div>
            <p className="text-sm leading-6 text-[var(--muted-foreground)]">
              Unified operator console for every seclab module - domain detection, authorized
              recon workflow, and CT-stream monitoring.
            </p>
          </div>
          {/* min-h-0 is required for a flex child to actually scroll instead of
              stretching its parent - without it, a growing nav list (one entry
              per module) silently overflows the sidebar's fixed height and
              overlaps/clips the Guardrails panel below instead of scrolling. */}
          <div className="mt-8 min-h-0 flex-1 overflow-y-auto pr-1">
            <SidebarNav />
          </div>
          <div className="subpanel mt-4 shrink-0 p-4 text-sm leading-6 text-[var(--muted-foreground)]">
            <div className="mb-2 text-xs font-semibold uppercase tracking-[0.16em] text-[var(--foreground)]">
              Guardrails
            </div>
            Scope, approval, execution, and finding states stay separated and audited across every
            module.
          </div>
        </div>
      </aside>
      <div className="min-w-0 flex-1">
        <Topbar />
        <div className="mt-4 lg:hidden">
          <SidebarNav mobile />
        </div>
        <main className="mt-6 pb-8">{children}</main>
      </div>
    </div>
  );
}
