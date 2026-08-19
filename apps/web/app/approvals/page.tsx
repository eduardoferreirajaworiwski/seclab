"use client";

import { useState } from "react";

import { PageHeader } from "@/components/shared/page-header";
import { StatusBadge } from "@/components/shared/status-badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/shared/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { getApiErrorMessage } from "@/lib/api/client";
import { useApproveApprovalMutation, usePendingApprovalsQuery, useRejectApprovalMutation } from "@/lib/api/hooks";
import { formatDateTime } from "@/lib/format";
import type { ApprovalRead } from "@/lib/types/api";

function ApprovalRow({ approval }: { approval: ApprovalRead }) {
  const [rationale, setRationale] = useState("");
  const approve = useApproveApprovalMutation(approval.id);
  const reject = useRejectApprovalMutation(approval.id);

  return (
    <div className="subpanel space-y-3 p-4">
      <div className="flex items-center justify-between gap-2">
        <div>
          <p className="text-sm font-semibold text-[var(--foreground-strong)]">{approval.subject_type}</p>
          <p className="text-xs text-[var(--muted-foreground)]">
            Requested by {approval.requested_by} - {formatDateTime(approval.created_at)}
          </p>
        </div>
        <StatusBadge status={approval.required_role} />
      </div>
      <p className="text-sm text-[var(--foreground)]">{approval.request_rationale}</p>
      <form
        className="flex flex-wrap items-center gap-2"
        onSubmit={(event) => {
          event.preventDefault();
        }}
      >
        <Input
          value={rationale}
          onChange={(event) => setRationale(event.target.value)}
          placeholder="Decision rationale"
          className="w-72"
        />
        <Button
          type="button"
          size="sm"
          disabled={approve.isPending || !rationale.trim()}
          onClick={() => approve.mutate({ rationale: rationale.trim() }, { onSuccess: () => setRationale("") })}
        >
          Approve
        </Button>
        <Button
          type="button"
          size="sm"
          variant="danger"
          disabled={reject.isPending || !rationale.trim()}
          onClick={() => reject.mutate({ rationale: rationale.trim() }, { onSuccess: () => setRationale("") })}
        >
          Reject
        </Button>
      </form>
      {approve.isError ? <p className="text-xs text-rose-200">{getApiErrorMessage(approve.error)}</p> : null}
      {reject.isError ? <p className="text-xs text-rose-200">{getApiErrorMessage(reject.error)}</p> : null}
    </div>
  );
}

export default function ApprovalsPage() {
  const pending = usePendingApprovalsQuery();

  return (
    <div className="space-y-8">
      <PageHeader
        title="Approval queue"
        description="Every state-changing action waits here for a human with a sufficient role. Requesters can never approve their own request."
      />

      <Card>
        <CardHeader>
          <CardTitle>Pending</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {pending.isPending ? <LoadingState title="Loading approvals" description="Fetching the pending queue." /> : null}
          {pending.isError ? (
            <ErrorState title="Could not load approvals" description={getApiErrorMessage(pending.error)} onRetry={() => pending.refetch()} />
          ) : null}
          {pending.data && pending.data.length === 0 ? (
            <EmptyState title="Nothing pending" description="New approval requests will show up here." />
          ) : null}
          {pending.data?.map((approval) => (
            <ApprovalRow key={approval.id} approval={approval} />
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
