"use client";

import { useState } from "react";

import { Explainer } from "@/components/shared/explainer";
import { ModuleTrackBadge } from "@/components/shared/module-track-badge";
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
  useCreateThreatLensDigestMutation,
  useCveWatchDigestQuery,
  useCveWatchDigestsQuery,
  useThreatLensDigestQuery,
  useThreatLensDigestsQuery,
} from "@/lib/api/hooks";
import { formatDateTime } from "@/lib/format";

type IntelSource = "threatlens" | "cve_watch";

const SOURCE_LABELS: Record<IntelSource, { label: string; description: string }> = {
  threatlens: {
    label: "ThreatLens",
    description: "Weekly security-news ingestion with deterministic attack-vector tagging.",
  },
  cve_watch: {
    label: "CVE Watch",
    description: "NVD + CISA KEV exploit tracker with deterministic product/vendor watchlist tagging.",
  },
};

export default function IntelPage() {
  const [source, setSource] = useState<IntelSource>("threatlens");
  const [lookbackDays, setLookbackDays] = useState(7);
  const [liveMode, setLiveMode] = useState(false);
  const [selectedThreatLensId, setSelectedThreatLensId] = useState<string | null>(null);
  const [selectedCveWatchId, setSelectedCveWatchId] = useState<string | null>(null);

  const threatlensDigests = useThreatLensDigestsQuery(20);
  const selectedThreatLensDigest = useThreatLensDigestQuery(selectedThreatLensId);
  const createThreatLensDigest = useCreateThreatLensDigestMutation();

  const cveWatchDigests = useCveWatchDigestsQuery(20);
  const selectedCveWatchDigest = useCveWatchDigestQuery(selectedCveWatchId);
  const createCveWatchDigest = useCreateCveWatchDigestMutation();

  const isThreatLens = source === "threatlens";
  const digests = isThreatLens ? threatlensDigests : cveWatchDigests;
  const createDigest = isThreatLens ? createThreatLensDigest : createCveWatchDigest;

  function selectSource(next: IntelSource) {
    setSource(next);
    setSelectedThreatLensId(null);
    setSelectedCveWatchId(null);
  }

  return (
    <div className="space-y-8">
      <PageHeader
        title="Intel"
        description="Weekly threat digests: security news (ThreatLens) and CVE / CISA-KEV exploit tracking (CVE Watch), both deterministically tagged with an AI-assisted narrative."
        action={<ModuleTrackBadge track="intel" />}
      />

      <Explainer title="O que este módulo faz">
        Contexto do mundo, não um workflow de ação: tagueamento de vetor de ataque é sempre
        determinístico (regras nomeadas); a narrativa em texto é gerada por IA (Gemini, com
        fallback para OpenAI) apenas quando configurada - senão cai num resumo determinístico.
      </Explainer>

      <div className="flex gap-2">
        {(Object.keys(SOURCE_LABELS) as IntelSource[]).map((key) => (
          <Button
            key={key}
            type="button"
            variant={source === key ? "default" : "outline"}
            size="sm"
            onClick={() => selectSource(key)}
          >
            {SOURCE_LABELS[key].label}
          </Button>
        ))}
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Run digest</CardTitle>
          <CardDescription>
            {isThreatLens
              ? "Offline uses mock feed fixtures with zero network calls; live mode fetches real security-news feeds."
              : "Offline uses trimmed NVD/KEV fixtures with zero network calls; live mode fetches both public feeds and merges them by CVE ID."}
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-wrap items-end gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (isThreatLens) {
                createThreatLensDigest.mutate(
                  { lookback_days: lookbackDays, offline_mode: !liveMode },
                  { onSuccess: (result) => setSelectedThreatLensId(result.digest_id) },
                );
              } else {
                createCveWatchDigest.mutate(
                  { lookback_days: lookbackDays, offline_mode: !liveMode },
                  { onSuccess: (result) => setSelectedCveWatchId(result.digest_id) },
                );
              }
            }}
          >
            <div className="flex flex-col gap-2">
              <Label htmlFor="lookback-days">Lookback (days)</Label>
              <Input
                id="lookback-days"
                type="number"
                min={1}
                max={isThreatLens ? 30 : 90}
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
                {isThreatLens ? "Live (real security-news feeds)" : "Live (real NVD / CISA KEV feeds)"}
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
            {isThreatLens
              ? threatlensDigests.data?.digests.map((item) => (
                  <button
                    key={item.digest_id}
                    onClick={() => setSelectedThreatLensId(item.digest_id)}
                    className="subpanel flex w-full flex-col gap-2 p-4 text-left transition-colors hover:border-[var(--border-accent)]"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-semibold text-[var(--foreground-strong)]">
                        {item.summary_headline}
                      </span>
                    </div>
                    <p className="text-xs text-[var(--muted-foreground)]">
                      {item.top_vectors.join(", ") || "No vectors tagged"}
                    </p>
                    <p className="text-xs text-[var(--subtle-foreground)]">{formatDateTime(item.created_at)}</p>
                  </button>
                ))
              : cveWatchDigests.data?.digests.map((item) => (
                  <button
                    key={item.digest_id}
                    onClick={() => setSelectedCveWatchId(item.digest_id)}
                    className="subpanel flex w-full flex-col gap-2 p-4 text-left transition-colors hover:border-[var(--border-accent)]"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-sm font-semibold text-[var(--foreground-strong)]">
                        {item.summary_headline}
                      </span>
                      {item.actively_exploited_count > 0 ? (
                        <StatusBadge status="high" label="Actively exploited" />
                      ) : null}
                    </div>
                    <p className="text-xs text-[var(--muted-foreground)]">{item.cve_count} CVE(s) tracked</p>
                    <p className="text-xs text-[var(--subtle-foreground)]">{formatDateTime(item.created_at)}</p>
                  </button>
                ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Report</CardTitle>
            <CardDescription>
              {isThreatLens
                ? selectedThreatLensId
                  ? "Full digest narrative and tagged articles."
                  : "Select a digest to view its report."
                : selectedCveWatchId
                  ? "Full digest narrative and tracked CVEs."
                  : "Select a digest to view its report."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {isThreatLens ? (
              <>
                {!selectedThreatLensId ? (
                  <EmptyState title="No digest selected" description="Run a new digest or pick one from the list." />
                ) : null}
                {selectedThreatLensDigest.isPending && selectedThreatLensId ? (
                  <LoadingState title="Loading report" description="Fetching digest detail." />
                ) : null}
                {selectedThreatLensDigest.data ? (
                  <>
                    <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap rounded-md bg-[var(--surface-inset)] p-4 text-xs leading-6 text-[var(--foreground)]">
                      {selectedThreatLensDigest.data.report_markdown}
                    </pre>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Title</TableHead>
                          <TableHead>Source</TableHead>
                          <TableHead>Vectors</TableHead>
                          <TableHead>Published</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {selectedThreatLensDigest.data.articles.map((article) => (
                          <TableRow key={article.link}>
                            <TableCell className="font-medium">{article.title}</TableCell>
                            <TableCell>{article.source}</TableCell>
                            <TableCell>
                              <div className="flex flex-wrap gap-1.5">
                                {article.vectors.map((vector) => (
                                  <StatusBadge key={vector} status={vector} />
                                ))}
                              </div>
                            </TableCell>
                            <TableCell className="text-xs text-[var(--muted-foreground)]">
                              {formatDateTime(article.published_at)}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </>
                ) : null}
              </>
            ) : (
              <>
                {!selectedCveWatchId ? (
                  <EmptyState title="No digest selected" description="Run a new digest or pick one from the list." />
                ) : null}
                {selectedCveWatchDigest.isPending && selectedCveWatchId ? (
                  <LoadingState title="Loading report" description="Fetching digest detail." />
                ) : null}
                {selectedCveWatchDigest.data ? (
                  <>
                    <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap rounded-md bg-[var(--surface-inset)] p-4 text-xs leading-6 text-[var(--foreground)]">
                      {selectedCveWatchDigest.data.report_markdown}
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
                        {selectedCveWatchDigest.data.cves.map((cve) => (
                          <TableRow key={cve.cve_id}>
                            <TableCell className="font-medium">{cve.cve_id}</TableCell>
                            <TableCell>{cve.cvss_score ?? "—"}</TableCell>
                            <TableCell>
                              {cve.is_actively_exploited ? (
                                <StatusBadge status="high" label="Yes" />
                              ) : (
                                <StatusBadge status="low" label="No" />
                              )}
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
              </>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
