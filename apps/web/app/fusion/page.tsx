"use client";

import { PageHeader } from "@/components/shared/page-header";
import { StatusBadge } from "@/components/shared/status-badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/shared/states";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { getApiErrorMessage } from "@/lib/api/client";
import { useFusionFeedQuery } from "@/lib/api/hooks";
import { formatDateTime } from "@/lib/format";

export default function FusionPage() {
  const feed = useFusionFeedQuery(20);

  return (
    <div className="space-y-8">
      <PageHeader
        title="Fusion"
        description="Read-only cross-module correlation feed: findings from Monitor, ThreatLens, and CVE Watch joined into one prioritized, explainable view. No own persistence - always computed fresh."
      />

      <Card>
        <CardHeader>
          <CardTitle>Correlated findings</CardTitle>
          <CardDescription>
            {feed.data
              ? `Generated ${formatDateTime(feed.data.generated_at)} - ${feed.data.monitor_match_count} monitor match(es) considered.`
              : "Sorted by score, descending."}
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {feed.isPending ? (
            <LoadingState title="Loading feed" description="Correlating recent activity across modules." />
          ) : null}
          {feed.isError ? (
            <ErrorState title="Could not load the fusion feed" description={getApiErrorMessage(feed.error)} onRetry={() => feed.refetch()} />
          ) : null}
          {feed.data && feed.data.findings.length === 0 ? (
            <EmptyState
              title="No correlated findings"
              description="Nothing in Monitor, ThreatLens, or CVE Watch currently correlates. Run a digest in those modules first."
            />
          ) : null}
          {feed.data?.findings.map((finding) => (
            <div key={finding.id} className="subpanel space-y-3 p-4">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold text-[var(--foreground-strong)]">{finding.title}</span>
                <StatusBadge status={finding.score >= 5 ? "high" : finding.score >= 2 ? "medium" : "low"} label={`Score ${finding.score}`} />
              </div>
              <p className="text-sm text-[var(--foreground)]">{finding.rationale}</p>
              <div className="space-y-1.5">
                {finding.signals.map((signal, index) => (
                  <div key={`${finding.id}-${index}`} className="flex items-center gap-2 text-xs text-[var(--muted-foreground)]">
                    <StatusBadge status={signal.severity} label={signal.source_module} />
                    <span>{signal.label}</span>
                    <span className="text-[var(--subtle-foreground)]">— {signal.detail}</span>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
