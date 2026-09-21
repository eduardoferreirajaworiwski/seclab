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
import { NativeSelect } from "@/components/ui/native-select";
import { getApiErrorMessage } from "@/lib/api/client";
import { useAnalysesQuery, useAnalysisQuery, useCreateAnalysisMutation } from "@/lib/api/hooks";
import { formatDateTime } from "@/lib/format";
import type { TargetType } from "@/lib/types/api";

export default function PhantomPage() {
  const [target, setTarget] = useState("");
  const [targetType, setTargetType] = useState<TargetType>("brand");
  const [liveMode, setLiveMode] = useState(false);
  const [selectedAnalysisId, setSelectedAnalysisId] = useState<string | null>(null);

  const analyses = useAnalysesQuery(20);
  const selectedAnalysis = useAnalysisQuery(selectedAnalysisId);
  const createAnalysis = useCreateAnalysisMutation();

  return (
    <div className="space-y-8">
      <PageHeader
        title="Phantom"
        description="Generate lookalike/typosquat domain variants for a brand or domain, check Certificate Transparency logs, enrich infrastructure, and score risk with explainable rules."
        action={<ModuleTrackBadge track="discovery" />}
      />

      <Explainer title="O que este módulo faz">
        Só detecta e pontua - não age sozinho. Cada domínio candidato recebe um score
        explicável (motivo do score é sempre mostrado); nada aqui vira execução automática.
      </Explainer>

      <Card>
        <CardHeader>
          <CardTitle>New analysis</CardTitle>
          <CardDescription>Offline uses mock providers with zero network calls; live queries crt.sh and RDAP for real.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-wrap items-end gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (!target.trim()) return;
              createAnalysis.mutate(
                {
                  target: target.trim(),
                  target_type: targetType,
                  max_variants: 10,
                  offline_mode: !liveMode,
                },
                { onSuccess: (result) => setSelectedAnalysisId(result.analysis_id) },
              );
            }}
          >
            <div className="flex flex-col gap-2">
              <Label htmlFor="target">Target</Label>
              <Input
                id="target"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                placeholder="acme or acme.com"
                className="w-64"
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="target-type">Type</Label>
              <NativeSelect
                id="target-type"
                value={targetType}
                onChange={(event) => setTargetType(event.target.value as TargetType)}
                className="w-40"
              >
                <option value="brand">Brand</option>
                <option value="domain">Domain</option>
              </NativeSelect>
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
                Live (real crt.sh / RDAP calls)
              </label>
            </div>
            <Button type="submit" disabled={createAnalysis.isPending}>
              {createAnalysis.isPending ? "Analyzing..." : "Run analysis"}
            </Button>
          </form>
          {liveMode ? (
            <p className="mt-4 text-xs text-[var(--muted-foreground)]">
              Live mode makes real outbound requests to crt.sh and rdap.org for each generated
              variant. This can take 10-20s for 10 variants.
            </p>
          ) : null}
          {createAnalysis.isError ? (
            <p className="mt-4 text-sm text-rose-200">{getApiErrorMessage(createAnalysis.error)}</p>
          ) : null}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-[380px_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Recent analyses</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {analyses.isPending ? <LoadingState title="Loading analyses" description="Fetching recent runs." /> : null}
            {analyses.isError ? (
              <ErrorState title="Could not load analyses" description={getApiErrorMessage(analyses.error)} />
            ) : null}
            {analyses.data && analyses.data.analyses.length === 0 ? (
              <EmptyState title="No analyses yet" description="Run one above to see results here." />
            ) : null}
            {analyses.data?.analyses.map((item) => (
              <button
                key={item.analysis_id}
                onClick={() => setSelectedAnalysisId(item.analysis_id)}
                className="subpanel flex w-full flex-col gap-2 p-4 text-left transition-colors hover:border-[var(--border-accent)]"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-[var(--foreground-strong)]">{item.target}</span>
                  <StatusBadge
                    status={item.high_priority_count > 0 ? "high" : item.medium_priority_count > 0 ? "medium" : "low"}
                  />
                </div>
                <p className="text-xs text-[var(--muted-foreground)]">{item.summary_headline}</p>
                <p className="text-xs text-[var(--subtle-foreground)]">{formatDateTime(item.created_at)}</p>
              </button>
            ))}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Report</CardTitle>
            <CardDescription>
              {selectedAnalysisId ? "Full findings and analyst summary." : "Select an analysis to view its report."}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!selectedAnalysisId ? (
              <EmptyState title="No analysis selected" description="Run a new analysis or pick one from the list." />
            ) : null}
            {selectedAnalysis.isPending && selectedAnalysisId ? (
              <LoadingState title="Loading report" description="Fetching analysis detail." />
            ) : null}
            {selectedAnalysis.data ? (
              <pre className="max-h-[70vh] overflow-auto whitespace-pre-wrap rounded-md bg-[var(--surface-inset)] p-4 text-xs leading-6 text-[var(--foreground)]">
                {selectedAnalysis.data.report_markdown}
              </pre>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
