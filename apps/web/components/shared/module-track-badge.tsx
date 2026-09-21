import { cn } from "@/lib/utils";

export type ModuleTrack = "discovery" | "bugbounty" | "intel";

const TRACK_LABELS: Record<ModuleTrack, string> = {
  discovery: "Descoberta",
  bugbounty: "Bug bounty",
  intel: "Intel",
};

const TRACK_CLASSES: Record<ModuleTrack, string> = {
  discovery:
    "border-[var(--track-discovery-border)] bg-[var(--track-discovery-soft)] text-[var(--track-discovery)]",
  bugbounty:
    "border-[var(--track-bugbounty-border)] bg-[var(--track-bugbounty-soft)] text-[var(--track-bugbounty)]",
  intel: "border-[var(--track-intel-border)] bg-[var(--track-intel-soft)] text-[var(--track-intel)]",
};

/**
 * Small consistent badge identifying which of the three module tracks
 * (Descoberta / Bug bounty / Intel) a module belongs to. Used in the
 * sidebar, the dashboard, and each module page's header so the
 * relationship between modules is visible without reading /docs.
 */
export function ModuleTrackBadge({ track, className }: { track: ModuleTrack; className?: string }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-full border px-2.5 py-0.5 text-[10px] font-semibold uppercase tracking-[0.1em]",
        TRACK_CLASSES[track],
        className,
      )}
    >
      {TRACK_LABELS[track]}
    </span>
  );
}
