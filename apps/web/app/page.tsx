"use client";

import Link from "next/link";

import { MetricCard } from "@/components/shared/metric-card";
import { PageHeader } from "@/components/shared/page-header";
import { ErrorState, LoadingState } from "@/components/shared/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  useAnalysesQuery,
  useCveWatchDigestsQuery,
  useHealthQuery,
  useMonitorMatchesQuery,
  usePendingApprovalsQuery,
  useProgramsQuery,
  useThreatLensDigestsQuery,
} from "@/lib/api/hooks";
import { getApiErrorMessage } from "@/lib/api/client";

export default function DashboardPage() {
  const health = useHealthQuery();
  const analyses = useAnalysesQuery(5);
  const programs = useProgramsQuery();
  const pendingApprovals = usePendingApprovalsQuery();
  const monitorMatches = useMonitorMatchesQuery(5);
  const threatlensDigests = useThreatLensDigestsQuery(5);
  const cveWatchDigests = useCveWatchDigestsQuery(5);

  const isPending = health.isPending || analyses.isPending || programs.isPending;
  const isError = health.isError || analyses.isError || programs.isError;

  if (isPending) {
    return <LoadingState title="Loading lab overview" description="Fetching status from every module." />;
  }

  if (isError) {
    return (
      <ErrorState
        title="Could not load the lab overview"
        description={getApiErrorMessage(health.error ?? analyses.error ?? programs.error)}
        onRetry={() => {
          health.refetch();
          analyses.refetch();
          programs.refetch();
        }}
      />
    );
  }

  const intelRuns = (threatlensDigests.data?.digests.length ?? 0) + (cveWatchDigests.data?.digests.length ?? 0);

  return (
    <div className="space-y-8">
      <PageHeader
        title="Personal security lab"
        description="One console over every module: lookalike-domain detection, authorized bug-bounty workflow, and real-time Certificate Transparency monitoring."
      />

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-5">
        <MetricCard
          label="Phantom analyses"
          value={String(analyses.data?.analyses.length ?? 0)}
          description="Most recent lookalike-domain runs."
          tone="accent"
        />
        <MetricCard
          label="Recon programs"
          value={String(programs.data?.length ?? 0)}
          description="Authorized bug-bounty programs registered."
          tone="info"
        />
        <MetricCard
          label="Pending approvals"
          value={String(pendingApprovals.data?.length ?? 0)}
          description="Hypotheses waiting on a human decision."
          tone={((pendingApprovals.data?.length ?? 0) > 0 ? "warning" : "neutral") as "warning" | "neutral"}
        />
        <MetricCard
          label="CT matches"
          value={String(monitorMatches.data?.length ?? 0)}
          description="Most recent Certificate Transparency hits."
          tone="success"
        />
        <MetricCard
          label="Intel digests"
          value={String(intelRuns)}
          description="Recent ThreatLens + CVE Watch digests combined."
          tone="accent"
        />
      </div>

      <div className="grid gap-4 lg:grid-cols-3">
        <Card>
          <CardHeader>
            <CardTitle>Phantom</CardTitle>
            <CardDescription>Lookalike/typosquat domain detection via Certificate Transparency.</CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/phantom">
              <Button variant="outline">Open Phantom</Button>
            </Link>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Recon</CardTitle>
            <CardDescription>
              Program scope, targets, hypotheses, human-approved execution, and per-target attack
              surface mapping.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/programs">
              <Button variant="outline">Open Programs</Button>
            </Link>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Monitor</CardTitle>
            <CardDescription>Real-time CT-stream matches, scored through the Phantom pipeline.</CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/monitor">
              <Button variant="outline">Open Monitor</Button>
            </Link>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Intel</CardTitle>
            <CardDescription>
              Weekly threat-news digests (ThreatLens) and CVE / CISA-KEV exploit tracking (CVE
              Watch), in one place.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/intel">
              <Button variant="outline">Open Intel</Button>
            </Link>
          </CardContent>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>Fusion</CardTitle>
            <CardDescription>Cross-module correlation feed: Monitor + ThreatLens + CVE Watch.</CardDescription>
          </CardHeader>
          <CardContent>
            <Link href="/fusion">
              <Button variant="outline">Open Fusion</Button>
            </Link>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Gateway status</CardTitle>
          <CardDescription>Modules mounted on this gateway instance.</CardDescription>
        </CardHeader>
        <CardContent className="flex flex-wrap gap-2 text-sm text-[var(--muted-foreground)]">
          {health.data?.modules.map((name) => (
            <span key={name} className="subpanel px-3 py-1">
              {name}
            </span>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
