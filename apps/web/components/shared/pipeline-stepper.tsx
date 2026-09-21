import { cn } from "@/lib/utils";

export type PipelineStep = {
  key: string;
  label: string;
  state: "complete" | "active" | "pending" | "blocked";
};

/**
 * Renders a horizontal pipeline of named steps with their state, e.g.
 * Target -> Hypothesis -> Approval -> Execution -> Finding. Purely
 * presentational: callers decide which step is active/blocked based on
 * their own domain state (see the Recon program detail page). Always
 * horizontal, at the top of the page it describes - not a persistent
 * sidebar element.
 */
export function PipelineStepper({ steps }: { steps: PipelineStep[] }) {
  return (
    <ol className="flex flex-wrap items-center gap-2">
      {steps.map((step, index) => (
        <li key={step.key} className="flex items-center gap-2">
          <span
            className={cn(
              "rounded-full border px-3 py-1.5 text-xs font-semibold",
              step.state === "complete" &&
                "border-[var(--stepper-complete-border)] bg-[var(--stepper-complete-soft)] text-[var(--stepper-complete)]",
              step.state === "active" &&
                "border-[var(--stepper-active-border)] bg-[var(--stepper-active-soft)] text-[var(--stepper-active)]",
              step.state === "pending" &&
                "border-[var(--border-subtle)] text-[var(--stepper-pending-foreground)]",
              step.state === "blocked" &&
                "border-[var(--stepper-blocked-border)] bg-[var(--stepper-blocked-soft)] text-[var(--stepper-blocked)]",
            )}
          >
            {step.label}
          </span>
          {index < steps.length - 1 ? (
            <span className="text-[var(--subtle-foreground)]" aria-hidden="true">
              →
            </span>
          ) : null}
        </li>
      ))}
    </ol>
  );
}
