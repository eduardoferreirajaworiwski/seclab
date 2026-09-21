import { cn } from "@/lib/utils";

/**
 * Inline "why this matters" callout. Used next to state-changing actions
 * (approve, queue execution, etc.) so the reasoning is visible at the
 * point of decision instead of buried in a separate docs page. Always
 * rendered inline (not a tooltip/collapsible) - the whole point is that
 * the explanation doesn't require an extra interaction to see.
 */
export function Explainer({
  title,
  children,
  className,
}: {
  title: string;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <div
      className={cn(
        "rounded-md border border-[var(--explainer-border)] bg-[var(--explainer-background)] px-4 py-3",
        className,
      )}
    >
      <p className="text-xs font-semibold uppercase tracking-[0.1em] text-[var(--explainer-foreground)]">
        {title}
      </p>
      <div className="mt-1 text-sm leading-6 text-[var(--muted-foreground)]">{children}</div>
    </div>
  );
}
