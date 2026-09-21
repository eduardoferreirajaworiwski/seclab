"use client";

import { Explainer } from "@/components/shared/explainer";
import { ModuleTrackBadge } from "@/components/shared/module-track-badge";
import { PageHeader } from "@/components/shared/page-header";
import { StatusBadge } from "@/components/shared/status-badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/shared/states";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { getApiErrorMessage } from "@/lib/api/client";
import { useMonitorMatchesQuery } from "@/lib/api/hooks";
import { formatDateTime } from "@/lib/format";

export default function MonitorPage() {
  const matches = useMonitorMatchesQuery(100);

  return (
    <div className="space-y-8">
      <PageHeader
        title="Monitor"
        description="Real-time Certificate Transparency stream matches, scored through the same Phantom pipeline used for on-demand analyses."
        action={<ModuleTrackBadge track="discovery" />}
      />

      <Explainer title="O que este módulo faz">
        É um stream ao vivo de Certificate Transparency, cruzado com o mesmo scoring do
        Phantom - cada match aqui é um domínio recém-emitido que bateu numa palavra-chave
        monitorada.
      </Explainer>

      <Card>
        <CardHeader>
          <CardTitle>Recent matches</CardTitle>
        </CardHeader>
        <CardContent>
          {matches.isPending ? (
            <LoadingState title="Loading matches" description="Fetching recent CT-stream hits." />
          ) : null}
          {matches.isError ? (
            <ErrorState title="Could not load matches" description={getApiErrorMessage(matches.error)} onRetry={() => matches.refetch()} />
          ) : null}
          {matches.data && matches.data.length === 0 ? (
            <EmptyState
              title="No matches yet"
              description="The monitor listener may not be running - start it with `seclab monitor run`."
            />
          ) : null}
          {matches.data && matches.data.length > 0 ? (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Domain</TableHead>
                  <TableHead>Keyword</TableHead>
                  <TableHead>Issuer</TableHead>
                  <TableHead>Score</TableHead>
                  <TableHead>Priority</TableHead>
                  <TableHead>Capture</TableHead>
                  <TableHead>Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {matches.data.map((match) => (
                  <TableRow key={match.id}>
                    <TableCell className="font-medium">{match.domain}</TableCell>
                    <TableCell>{match.matched_keyword}</TableCell>
                    <TableCell>{match.issuer}</TableCell>
                    <TableCell>{match.score}</TableCell>
                    <TableCell>
                      <StatusBadge status={match.priority} />
                    </TableCell>
                    <TableCell>
                      <StatusBadge status={match.capture_status} />
                    </TableCell>
                    <TableCell className="text-xs text-[var(--muted-foreground)]">
                      {formatDateTime(match.created_at)}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
