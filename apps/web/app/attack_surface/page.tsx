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
import { useCreateSurfaceScanMutation, useSurfaceScanQuery, useSurfaceScansQuery } from "@/lib/api/hooks";
import { formatDateTime } from "@/lib/format";

export default function AttackSurfacePage() {
  const [domain, setDomain] = useState("");
  const [allowedDomains, setAllowedDomains] = useState("");
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  const scans = useSurfaceScansQuery(20);
  const selectedScan = useSurfaceScanQuery(selectedScanId);
  const createScan = useCreateSurfaceScanMutation();

  return (
    <div className="space-y-8">
      <PageHeader
        title="Attack Surface"
        description="Lightweight external ASM: CT-based subdomain discovery and bounded TCP-connect port probing, gated by an explicit allowlist. No allowlist match means nothing is scanned."
      />

      <Card>
        <CardHeader>
          <CardTitle>New scan</CardTitle>
          <CardDescription>
            Comma-separated allowlist. The domain is validated against it before any discovery or
            probing happens - out-of-scope domains short-circuit with zero outbound calls.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="flex flex-wrap items-end gap-4"
            onSubmit={(event) => {
              event.preventDefault();
              if (!domain.trim()) return;
              createScan.mutate(
                {
                  target: { domain: domain.trim() },
                  scope_policy: {
                    allowed_domains: allowedDomains
                      .split(",")
                      .map((item) => item.trim())
                      .filter(Boolean),
                  },
                },
                { onSuccess: (result) => setSelectedScanId(result.scan_id) },
              );
            }}
          >
            <div className="flex flex-col gap-2">
              <Label htmlFor="domain">Domain</Label>
              <Input
                id="domain"
                value={domain}
                onChange={(event) => setDomain(event.target.value)}
                placeholder="example.com"
                className="w-56"
              />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="allowlist">Allowed domains</Label>
              <Input
                id="allowlist"
                value={allowedDomains}
                onChange={(event) => setAllowedDomains(event.target.value)}
                placeholder="example.com, *.example.com"
                className="w-72"
              />
            </div>
            <Button type="submit" disabled={createScan.isPending}>
              {createScan.isPending ? "Scanning..." : "Run scan"}
            </Button>
          </form>
          {createScan.isError ? (
            <p className="mt-4 text-sm text-rose-200">{getApiErrorMessage(createScan.error)}</p>
          ) : null}
        </CardContent>
      </Card>

      <div className="grid gap-6 lg:grid-cols-[380px_1fr]">
        <Card>
          <CardHeader>
            <CardTitle>Recent scans</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            {scans.isPending ? (
              <LoadingState title="Loading scans" description="Fetching recent runs." />
            ) : null}
            {scans.isError ? (
              <ErrorState
                title="Could not load scans"
                description={getApiErrorMessage(scans.error)}
                onRetry={() => scans.refetch()}
              />
            ) : null}
            {scans.data && scans.data.scans.length === 0 ? (
              <EmptyState title="No scans yet" description="Run one above to see results here." />
            ) : null}
            {scans.data?.scans.map((item) => (
              <button
                key={item.scan_id}
                onClick={() => setSelectedScanId(item.scan_id)}
                className="subpanel flex w-full flex-col gap-2 p-4 text-left transition-colors hover:border-[var(--border-accent)]"
              >
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-[var(--foreground-strong)]">{item.domain}</span>
                  <StatusBadge status={item.in_scope ? "approved" : "rejected"} label={item.in_scope ? "In scope" : "Out of scope"} />
                </div>
                <p className="text-xs text-[var(--muted-foreground)]">
                  {item.host_count} host(s), {item.exposure_tag_count} exposure tag(s)
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
              {selectedScanId ? "Full findings for this scan." : "Select a scan to view its report."}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            {!selectedScanId ? (
              <EmptyState title="No scan selected" description="Run a new scan or pick one from the list." />
            ) : null}
            {selectedScan.isPending && selectedScanId ? (
              <LoadingState title="Loading report" description="Fetching scan detail." />
            ) : null}
            {selectedScan.data ? (
              <>
                <pre className="max-h-[50vh] overflow-auto whitespace-pre-wrap rounded-md bg-[var(--surface-inset)] p-4 text-xs leading-6 text-[var(--foreground)]">
                  {selectedScan.data.report_markdown}
                </pre>
                {selectedScan.data.hosts.length > 0 ? (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Hostname</TableHead>
                        <TableHead>IP addresses</TableHead>
                        <TableHead>Open ports</TableHead>
                        <TableHead>Exposure tags</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {selectedScan.data.hosts.map((host) => (
                        <TableRow key={host.hostname}>
                          <TableCell className="font-medium">{host.hostname}</TableCell>
                          <TableCell className="text-xs text-[var(--muted-foreground)]">
                            {host.ip_addresses.join(", ") || "—"}
                          </TableCell>
                          <TableCell className="text-xs text-[var(--muted-foreground)]">
                            {host.open_ports.join(", ") || "none"}
                          </TableCell>
                          <TableCell>
                            <div className="flex flex-wrap gap-1.5">
                              {host.unexpected_exposure_tags.map((tag) => (
                                <StatusBadge key={tag} status="high" label={tag} />
                              ))}
                            </div>
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
