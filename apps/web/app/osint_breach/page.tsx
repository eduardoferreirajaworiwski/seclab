"use client";

import { useState } from "react";

import { PageHeader } from "@/components/shared/page-header";
import { StatusBadge } from "@/components/shared/status-badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/shared/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { NativeSelect } from "@/components/ui/native-select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getApiErrorMessage } from "@/lib/api/client";
import { useBreachCheckQuery, useBreachChecksQuery, useCreateBreachCheckMutation } from "@/lib/api/hooks";
import { formatDateTime } from "@/lib/format";
import type { WatchedIdentifier } from "@/lib/types/api";

export default function OsintBreachPage() {
  const [identifier, setIdentifier] = useState("");
  const [identifierType, setIdentifierType] = useState<"email" | "domain">("email");
  const [pending, setPending] = useState<WatchedIdentifier[]>([]);
  const [liveMode, setLiveMode] = useState(false);
  const [selectedCheckId, setSelectedCheckId] = useState<string | null>(null);

  const checks = useBreachChecksQuery(20);
  const selectedCheck = useBreachCheckQuery(selectedCheckId);
  const createCheck = useCreateBreachCheckMutation();

  return (
    <div className="space-y-8">
      <PageHeader
        title="OSINT Breach"
        description="Breach/leak watcher for tracked emails and domains, offline-fixture-first with an optional live HIBP lookup."
      />

      <Card>
        <CardHeader>
          <CardTitle>New check</CardTitle>
          <CardDescription>
            Add one or more watched identifiers, then run the check. Domain identifiers always
            resolve against the offline fixture set regardless of mode.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <form
            className="flex flex-wrap items-end gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (!identifier.trim()) return;
              setPending((prev) => [...prev, { identifier: identifier.trim(), identifier_type: identifierType }]);
              setIdentifier("");
            }}
          >
            <div className="flex flex-col gap-2">
              <Label htmlFor="identifier">Identifier</Label>
              <Input
                id="identifier"
                value={identifier}
                onChange={(event) => setIdentifier(event.target.value)}
                placeholder="you@example.com or example.com"
                className="w-64"
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="identifier-type">Type</Label>
              <NativeSelect
                id="identifier-type"
                value={identifierType}
                onChange={(event) => setIdentifierType(event.target.value as "email" | "domain")}
                className="w-32"
              >
                <option value="email">Email</option>
                <option value="domain">Domain</option>
              </NativeSelect>
            </div>
            <Button type="submit" variant="secondary">
              Add to check
            </Button>
          </form>

          {pending.length > 0 ? (
            <div className="flex flex-wrap gap-2">
              {pending.map((item, index) => (
                <span key={`${item.identifier}-${index}`} className="subpanel flex items-center gap-2 px-3 py-1.5 text-xs">
                  {item.identifier} ({item.identifier_type})
                  <button
                    type="button"
                    onClick={() => setPending((prev) => prev.filter((_, i) => i !== index))}
                    className="text-[var(--muted-foreground)] hover:text-[var(--foreground)]"
                  >
                    ×
                  </button>
                </span>
              ))}
            </div>
          ) : null}

          <div className="flex flex-wrap items-end gap-4">
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
                Live (real HIBP lookups for email identifiers)
              </label>
            </div>
            <Button
              type="button"
              disabled={pending.length === 0 || createCheck.isPending}
              onClick={() =>
                createCheck.mutate(
                  { identifiers: pending, offline_mode: !liveMode },
                  {
                    onSuccess: (result) => {
                      setSelectedCheckId(result.check_id);
                      setPending([]);
                    },
                  },
                )
              }
            >
              {createCheck.isPending ? "Running check..." : "Run check"}
            </Button>
          </div>
          {createCheck.isError ? (
            <p className="text-sm text-rose-200">{getApiErrorMessage(createCheck.error)}</p>
          ) : null}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-[380px_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Recent checks</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {checks.isPending ? (
              <LoadingState title="Loading checks" description="Fetching recent runs." />
            ) : null}
            {checks.isError ? (
              <ErrorState
                title="Could not load checks"
                description={getApiErrorMessage(checks.error)}
                onRetry={() => checks.refetch()}
              />
            ) : null}
            {checks.data && checks.data.checks.length === 0 ? (
              <EmptyState title="No checks yet" description="Run one above to see results here." />
            ) : null}
            {checks.data?.checks.map((item) => (
              <button
                key={item.check_id}
                onClick={() => setSelectedCheckId(item.check_id)}
                className="subpanel flex w-full flex-col gap-2 p-4 text-left transition-colors hover:border-[var(--border-accent)]"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-[var(--foreground-strong)]">
                    {item.summary_headline}
                  </span>
                  {item.exposure_count > 0 ? <StatusBadge status="high" label={`${item.exposure_count} exposures`} /> : null}
                </div>
                <p className="text-xs text-[var(--muted-foreground)]">
                  {item.identifier_count} identifier(s) checked
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
              {selectedCheckId ? "Full exposure report." : "Select a check to view its report."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {!selectedCheckId ? (
              <EmptyState title="No check selected" description="Run a new check or pick one from the list." />
            ) : null}
            {selectedCheck.isPending && selectedCheckId ? (
              <LoadingState title="Loading report" description="Fetching check detail." />
            ) : null}
            {selectedCheck.data ? (
              <>
                <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap rounded-md bg-[var(--surface-inset)] p-4 text-xs leading-6 text-[var(--foreground)]">
                  {selectedCheck.data.report_markdown}
                </pre>
                {selectedCheck.data.exposures.length > 0 ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Identifier</TableHead>
                        <TableHead>Breach</TableHead>
                        <TableHead>Data classes</TableHead>
                        <TableHead>Breach date</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {selectedCheck.data.exposures.map((exposure, index) => (
                        <TableRow key={`${exposure.identifier}-${exposure.breach_name}-${index}`}>
                          <TableCell className="font-medium">{exposure.identifier}</TableCell>
                          <TableCell>{exposure.breach_name}</TableCell>
                          <TableCell className="text-xs text-[var(--muted-foreground)]">
                            {exposure.data_classes.join(", ") || "—"}
                          </TableCell>
                          <TableCell className="text-xs text-[var(--muted-foreground)]">
                            {formatDateTime(exposure.breach_date)}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                ) : null}
              </>
            ) : null}
          </CardContent>
        </Card>
      </div>
    </div>
  );
}
