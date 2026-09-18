"use client";

import { useState } from "react";

import { PageHeader } from "@/components/shared/page-header";
import { StatusBadge } from "@/components/shared/status-badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/shared/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getApiErrorMessage } from "@/lib/api/client";
import {
  useCreateCveWatchDigestMutation,
  useCveWatchDigestQuery,
  useCveWatchDigestsQuery,
} from "@/lib/api/hooks";
import { formatDateTime } from "@/lib/format";

export default function CveWatchPage() {
  const [lookbackDays, setLookbackDays] = useState(7);
  const [liveMode, setLiveMode] = useState(false);
  const [selectedDigestId, setSelectedDigestId] = useState<string | null>(null);

  const digests = useCveWatchDigestsQuery(20);
  const selectedDigest = useCveWatchDigestQuery(selectedDigestId);
  const createDigest = useCreateCveWatchDigestMutation();

  return (
    <div className="space-y-8">
      <PageHeader
        title="CVE Watch"
        description="NVD + CISA KEV exploit tracker with deterministic product/vendor watchlist tagging."
      />

      <Card>
        <CardHeader>
          <CardTitle>Run digest</CardTitle>
          <CardDescription>
            Offline uses trimmed NVD/KEV fixtures with zero network calls; live mode fetches both
            public feeds and merges them by CVE ID.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-wrap items-end gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              createDigest.mutate(
                { lookback_days: lookbackDays, offline_mode: !liveMode },
                { onSuccess: (result) => setSelectedDigestId(result.digest_id) },
              );
            }}
          >
            <div className="flex flex-col gap-2">
              <Label htmlFor="lookback-days">Lookback (days)</Label>
              <Input
                id="lookback-days"
                type="number"
                min={1}
                max={90}
                value={lookbackDays}
                onChange={(event) => setLookbackDays(Number(event.target.value) || 7)}
                className="w-32"
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="live-mode">Data source</Label>
              <label htmlFor="live-mode" className="flex h-9 items-center gap-2 text-sm text-[var(--foreground)]">
                <input
                  id="live-mode"
                  type="checkbox"
                  checked={liveMode}
                  onChange={(event) => setLiveMode(event.target.checked)}
                  className="h-4 w-4 rounded border-[var(--border-subtle)]"
                />
                Live (real NVD / CISA KEV feeds)
              </label>
            </div>
            <Button type="submit" disabled={createDigest.isPending}>
              {createDigest.isPending ? "Running digest..." : "Run digest"}
            </Button>
          </form>
          {createDigest.isError ? (
            <p className="mt-4 text-sm text-rose-200">{getApiErrorMessage(createDigest.error)}</p>
          ) : null}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-[380px_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Recent digests</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {digests.isPending ? (
              <LoadingState title="Loading digests" description="Fetching recent runs." />
            ) : null}
            {digests.isError ? (
              <ErrorState
                title="Could not load digests"
                description={getApiErrorMessage(digests.error)}
                onRetry={() => digests.refetch()}
              />
            ) : null}
            {digests.data && digests.data.digests.length === 0 ? (
              <EmptyState title="No digests yet" description="Run one above to see results here." />
            ) : null}
            {digests.data?.digests.map((item) => (
              <button
                key={item.digest_id}
                onClick={() => setSelectedDigestId(item.digest_id)}
                className="subpanel flex w-full flex-col gap-2 p-4 text-left transition-colors hover:border-[var(--border-accent)]"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-[var(--foreground-strong)]">
                    {item.summary_headline}
                  </span>
                  {item.actively_exploited_count > 0 ? <StatusBadge status="high" label="Actively exploited" /> : null}
                </div>
                <p className="text-xs text-[var(--muted-foreground)]">
                  {item.cve_count} CVE(s) tracked
                </p>
                <p className="text-xs text-[var(--subtle-foreground)]">{formatDateTime(item.created_at)}</p>
              </button>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Report</CardTitle>
            <CardDescription>
              {selectedDigestId ? "Full digest narrative and tracked CVEs." : "Select a digest to view its report."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {!selectedDigestId ? (
              <EmptyState title="No digest selected" description="Run a new digest or pick one from the list." />
            ) : null}
            {selectedDigest.isPending && selectedDigestId ? (
              <LoadingState title="Loading report" description="Fetching digest detail." />
            ) : null}
            {selectedDigest.data ? (
              <>
                <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap rounded-md bg-[var(--surface-inset)] p-4 text-xs leading-6 text-[var(--foreground)]">
                  {selectedDigest.data.report_markdown}
                </pre>
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>CVE</TableHead>
                      <TableHead>CVSS</TableHead>
                      <TableHead>Exploited</TableHead>
                      <TableHead>Matched products</TableHead>
                      <TableHead>Published</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {selectedDigest.data.cves.map((cve) => (
                      <TableRow key={cve.cve_id}>
                        <TableCell className="font-medium">{cve.cve_id}</TableCell>
                        <TableCell>{cve.cvss_score ?? "—"}</TableCell>
                        <TableCell>
                          {cve.is_actively_exploited ? <StatusBadge status="high" label="Yes" /> : <StatusBadge status="low" label="No" />}
                        </TableCell>
                        <TableCell className="text-xs text-[var(--muted-foreground)]">
                          {cve.matched_products.join(", ") || "—"}
                        </TableCell>
                        <TableCell className="text-xs text-[var(--muted-foreground)]">
                          {formatDateTime(cve.published_at)}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
