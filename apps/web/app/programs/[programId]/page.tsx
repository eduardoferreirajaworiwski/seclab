"use client";

import { use, useState } from "react";

import { PageHeader } from "@/components/shared/page-header";
import { StatusBadge } from "@/components/shared/status-badge";
import { EmptyState, ErrorState, LoadingState } from "@/components/shared/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { getApiErrorMessage } from "@/lib/api/client";
import {
  useCompleteExecutionMutation,
  useCreateHypothesisMutation,
  useCreateTargetMutation,
  useHypothesisExecutionsQuery,
  useProgramFindingsQuery,
  useProgramHypothesesQuery,
  useProgramQuery,
  useProgramTargetsQuery,
  useQueueExecutionMutation,
  useRequestApprovalMutation,
} from "@/lib/api/hooks";
import { formatDateTime } from "@/lib/format";
import type { HypothesisRead, TargetRead } from "@/lib/types/api";

function NewTargetForm({ programId }: { programId: number }) {
  const [identifier, setIdentifier] = useState("");
  const createTarget = useCreateTargetMutation(programId);

  return (
    <form
      className="flex flex-wrap items-end gap-3"
      onSubmit={(event) => {
        event.preventDefault();
        if (!identifier.trim()) return;
        createTarget.mutate(
          { identifier: identifier.trim(), target_type: "domain" },
          { onSuccess: () => setIdentifier("") },
        );
      }}
    >
      <div className="flex flex-col gap-2">
        <Label htmlFor="target-identifier">New target (domain)</Label>
        <Input
          id="target-identifier"
          value={identifier}
          onChange={(event) => setIdentifier(event.target.value)}
          placeholder="app.example.com"
          className="w-64"
        />
      </div>
      <Button type="submit" size="sm" disabled={createTarget.isPending}>
        Add target
      </Button>
      {createTarget.isError ? <p className="text-xs text-rose-200">{getApiErrorMessage(createTarget.error)}</p> : null}
    </form>
  );
}

function NewHypothesisForm({ programId, target }: { programId: number; target: TargetRead }) {
  const [title, setTitle] = useState("");
  const [description, setDescription] = useState("");
  const createHypothesis = useCreateHypothesisMutation(programId, target.id);

  if (!target.in_scope) {
    return <p className="text-xs text-[var(--muted-foreground)]">Out of scope - hypotheses disabled.</p>;
  }

  return (
    <form
      className="space-y-2"
      onSubmit={(event) => {
        event.preventDefault();
        if (!title.trim() || !description.trim()) return;
        createHypothesis.mutate(
          { title: title.trim(), description: description.trim() },
          {
            onSuccess: () => {
              setTitle("");
              setDescription("");
            },
          },
        );
      }}
    >
      <Input value={title} onChange={(event) => setTitle(event.target.value)} placeholder="Hypothesis title" />
      <Textarea
        value={description}
        onChange={(event) => setDescription(event.target.value)}
        placeholder="What do you suspect, and why?"
      />
      <Button type="submit" size="sm" disabled={createHypothesis.isPending}>
        Add hypothesis for {target.identifier}
      </Button>
      {createHypothesis.isError ? (
        <p className="text-xs text-rose-200">{getApiErrorMessage(createHypothesis.error)}</p>
      ) : null}
    </form>
  );
}

function HypothesisRow({ hypothesis, programId }: { hypothesis: HypothesisRead; programId: number }) {
  const [rationale, setRationale] = useState("");
  const [actionPlan, setActionPlan] = useState("");
  const [completeSummary, setCompleteSummary] = useState("");
  const executions = useHypothesisExecutionsQuery(hypothesis.id);
  const requestApproval = useRequestApprovalMutation(hypothesis.id, programId);
  const queueExecution = useQueueExecutionMutation(hypothesis.id);
  const latestExecution = executions.data?.[0] ?? null;
  const completeExecution = useCompleteExecutionMutation(latestExecution?.id ?? 0, hypothesis.id, programId);

  return (
    <div className="subpanel space-y-3 p-4">
      <div className="flex items-center justify-between gap-2">
        <div>
          <p className="text-sm font-semibold text-[var(--foreground-strong)]">{hypothesis.title}</p>
          <p className="text-xs text-[var(--muted-foreground)]">{hypothesis.description}</p>
        </div>
        <StatusBadge status={hypothesis.status} />
      </div>

      {hypothesis.status === "draft" ? (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (!rationale.trim()) return;
            requestApproval.mutate({ rationale: rationale.trim() }, { onSuccess: () => setRationale("") });
          }}
        >
          <Input
            value={rationale}
            onChange={(event) => setRationale(event.target.value)}
            placeholder="Rationale for human review"
            className="w-72"
          />
          <Button type="submit" size="sm" variant="secondary" disabled={requestApproval.isPending}>
            Request approval
          </Button>
        </form>
      ) : null}

      {hypothesis.status === "approved" && !latestExecution ? (
        <form
          className="flex flex-wrap items-end gap-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (!actionPlan.trim()) return;
            queueExecution.mutate({ action_plan: actionPlan.trim() }, { onSuccess: () => setActionPlan("") });
          }}
        >
          <Input
            value={actionPlan}
            onChange={(event) => setActionPlan(event.target.value)}
            placeholder="Action plan for the approved execution"
            className="w-72"
          />
          <Button type="submit" size="sm" disabled={queueExecution.isPending}>
            Queue execution
          </Button>
        </form>
      ) : null}

      {latestExecution && latestExecution.status !== "completed" ? (
        <form
          className="space-y-2"
          onSubmit={(event) => {
            event.preventDefault();
            if (!completeSummary.trim()) return;
            completeExecution.mutate(
              {
                output_summary: completeSummary.trim(),
                finding_title: `Finding for: ${hypothesis.title}`,
                finding_description: completeSummary.trim(),
                finding_severity: hypothesis.severity,
              },
              { onSuccess: () => setCompleteSummary("") },
            );
          }}
        >
          <Textarea
            value={completeSummary}
            onChange={(event) => setCompleteSummary(event.target.value)}
            placeholder="Execution output summary (becomes the finding description)"
          />
          <Button type="submit" size="sm" disabled={completeExecution.isPending}>
            Complete execution &amp; record finding
          </Button>
        </form>
      ) : null}

      {latestExecution ? (
        <p className="text-xs text-[var(--muted-foreground)]">
          Latest execution: <StatusBadge status={latestExecution.status} />
        </p>
      ) : null}
    </div>
  );
}

export default function ProgramDetailPage({ params }: { params: Promise<{ programId: string }> }) {
  const { programId: programIdParam } = use(params);
  const programId = Number(programIdParam);

  const program = useProgramQuery(programId);
  const targets = useProgramTargetsQuery(programId);
  const hypotheses = useProgramHypothesesQuery(programId);
  const findings = useProgramFindingsQuery(programId);

  if (program.isPending) {
    return <LoadingState title="Loading program" description="Fetching scope and workflow state." />;
  }

  if (program.isError || !program.data) {
    return (
      <ErrorState
        title="Could not load this program"
        description={getApiErrorMessage(program.error)}
        onRetry={() => program.refetch()}
      />
    );
  }

  return (
    <div className="space-y-8">
      <PageHeader title={program.data.name} description={program.data.description || "No description."} />

      <Card>
        <CardHeader>
          <CardTitle>Scope policy</CardTitle>
          <CardDescription>No allowlist means nothing is in scope.</CardDescription>
        </CardHeader>
        <CardContent className="text-sm text-[var(--muted-foreground)]">
          Allowed: {program.data.scope_policy.allowed_domains?.join(", ") || "none"}
          <br />
          Denied: {program.data.scope_policy.denied_domains?.join(", ") || "none"}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Targets</CardTitle>
          <CardDescription>Every target is validated against the scope policy on creation.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <NewTargetForm programId={programId} />
          {targets.isPending ? <LoadingState title="Loading targets" description="Fetching targets." /> : null}
          {targets.data && targets.data.length === 0 ? (
            <EmptyState title="No targets yet" description="Add one above." />
          ) : null}
          <div className="grid gap-3 md:grid-cols-2">
            {targets.data?.map((target) => (
              <div key={target.id} className="subpanel space-y-2 p-4">
                <div className="flex items-center justify-between gap-2">
                  <span className="text-sm font-semibold text-[var(--foreground-strong)]">{target.identifier}</span>
                  <StatusBadge status={target.in_scope ? "approved" : "rejected"} label={target.in_scope ? "In scope" : "Out of scope"} />
                </div>
                <p className="text-xs text-[var(--muted-foreground)]">{target.scope_reason}</p>
                <NewHypothesisForm programId={programId} target={target} />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Hypotheses</CardTitle>
          <CardDescription>Draft, request approval, and (once approved) queue and complete execution.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {hypotheses.isPending ? <LoadingState title="Loading hypotheses" description="Fetching hypotheses." /> : null}
          {hypotheses.data && hypotheses.data.length === 0 ? (
            <EmptyState title="No hypotheses yet" description="Add one from a target above." />
          ) : null}
          {hypotheses.data?.map((hypothesis) => (
            <HypothesisRow key={hypothesis.id} hypothesis={hypothesis} programId={programId} />
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Findings</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {findings.data && findings.data.length === 0 ? (
            <EmptyState title="No findings yet" description="Findings appear once an execution is completed." />
          ) : null}
          {findings.data?.map((finding) => (
            <div key={finding.id} className="subpanel space-y-1 p-4">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold text-[var(--foreground-strong)]">{finding.title}</span>
                <StatusBadge status={finding.severity} />
              </div>
              <p className="text-xs text-[var(--muted-foreground)]">{finding.description}</p>
              <p className="text-xs text-[var(--subtle-foreground)]">{formatDateTime(finding.created_at)}</p>
            </div>
          ))}
        </CardContent>
      </Card>
    </div>
  );
}
