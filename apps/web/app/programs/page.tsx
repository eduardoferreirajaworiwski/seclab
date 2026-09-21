"use client";

import Link from "next/link";
import { useState } from "react";

import { PageHeader } from "@/components/shared/page-header";
import { EmptyState, ErrorState, LoadingState } from "@/components/shared/states";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { getApiErrorMessage } from "@/lib/api/client";
import { useCreateProgramMutation, useProgramsQuery } from "@/lib/api/hooks";
import { formatDateTime } from "@/lib/format";

export default function ProgramsPage() {
  const programs = useProgramsQuery();
  const createProgram = useCreateProgramMutation();

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [allowedDomains, setAllowedDomains] = useState("");

  return (
    <div className="space-y-8">
      <PageHeader
        title="Recon programs"
        description="Every target, hypothesis, and execution lives under a program with an explicit scope policy. No allowlist means nothing is in scope - by design. Fluxo dentro de um programa: Target (checado contra o escopo) → Hipótese → Aprovação humana → Execução → Finding."
      />

      <Card>
        <CardHeader>
          <CardTitle>New program</CardTitle>
          <CardDescription>Comma-separated allowlist. Wildcards like *.example.com are supported.</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="grid gap-4 md:grid-cols-2"
            onSubmit={(event) => {
              event.preventDefault();
              if (!name.trim()) return;
              createProgram.mutate(
                {
                  name: name.trim(),
                  description: description.trim(),
                  scope_policy: {
                    allowed_domains: allowedDomains
                      .split(",")
                      .map((item) => item.trim())
                      .filter(Boolean),
                  },
                },
                {
                  onSuccess: () => {
                    setName("");
                    setDescription("");
                    setAllowedDomains("");
                  },
                },
              );
            }}
          >
            <div className="flex flex-col gap-2">
              <Label htmlFor="program-name">Name</Label>
              <Input id="program-name" value={name} onChange={(event) => setName(event.target.value)} />
            </div>
            <div className="flex flex-col gap-2">
              <Label htmlFor="program-allowlist">Allowed domains</Label>
              <Input
                id="program-allowlist"
                value={allowedDomains}
                onChange={(event) => setAllowedDomains(event.target.value)}
                placeholder="example.com, *.example.org"
              />
            </div>
            <div className="flex flex-col gap-2 md:col-span-2">
              <Label htmlFor="program-description">Description</Label>
              <Textarea
                id="program-description"
                value={description}
                onChange={(event) => setDescription(event.target.value)}
              />
            </div>
            <div className="md:col-span-2">
              <Button type="submit" disabled={createProgram.isPending}>
                {createProgram.isPending ? "Creating..." : "Create program"}
              </Button>
              {createProgram.isError ? (
                <p className="mt-3 text-sm text-rose-200">{getApiErrorMessage(createProgram.error)}</p>
              ) : null}
            </div>
          </form>
        </CardContent>
      </Card>

      {programs.isPending ? <LoadingState title="Loading programs" description="Fetching program inventory." /> : null}
      {programs.isError ? (
        <ErrorState title="Could not load programs" description={getApiErrorMessage(programs.error)} onRetry={() => programs.refetch()} />
      ) : null}
      {programs.data && programs.data.length === 0 ? (
        <EmptyState title="No programs yet" description="Create one above to start authorizing targets." />
      ) : null}

      <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
        {programs.data?.map((program) => (
          <Link key={program.id} href={`/programs/${program.id}`}>
            <Card className="h-full transition-colors hover:border-[var(--border-accent)]">
              <CardHeader>
                <CardTitle>{program.name}</CardTitle>
                <CardDescription>{program.description || "No description."}</CardDescription>
              </CardHeader>
              <CardContent className="space-y-2 text-xs text-[var(--muted-foreground)]">
                <p>Owner: {program.owner}</p>
                <p>Allowlist: {program.scope_policy.allowed_domains?.join(", ") || "none"}</p>
                <p>Created {formatDateTime(program.created_at)}</p>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  );
}
