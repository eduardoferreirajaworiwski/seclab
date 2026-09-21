"use client";

import { useRouter } from "next/navigation";
import { useEffect } from "react";

import { ApiKeyForm } from "@/components/shared/api-key-form";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { useConnectionStatus } from "@/lib/api/connection-status";

const INIT_COMMAND = "uv run seclab init";
const USERS_COMMAND = 'uv run seclab users create <username> --role analyst';

function StatusMessage({ status }: { status: "invalid_key" | "unreachable" | "checking" }) {
  if (status === "checking") {
    return <p className="text-sm text-[var(--muted-foreground)]">Testando a conexão...</p>;
  }
  if (status === "invalid_key") {
    return (
      <p className="text-sm leading-6 text-rose-200">
        A chave foi salva, mas o gateway recusou (401). Confira se você copiou a chave inteira, ou
        gere uma nova com <code className="font-mono">{USERS_COMMAND}</code>.
      </p>
    );
  }
  return (
    <p className="text-sm leading-6 text-rose-200">
      Não consegui falar com o gateway em <code className="font-mono">NEXT_PUBLIC_SECLAB_API_URL</code>.
      Confirme que o comando abaixo está rodando em outro terminal:
      <br />
      <code className="mt-1 block font-mono">
        uvicorn seclab_gateway.main:app --reload --app-dir apps/gateway/src
      </code>
    </p>
  );
}

export default function OnboardingPage() {
  const { status, refetch } = useConnectionStatus();
  const router = useRouter();

  useEffect(() => {
    if (status === "connected") {
      router.replace("/");
    }
  }, [status, router]);


  return (
    <div className="mx-auto max-w-2xl space-y-8 py-8">
      <div className="space-y-3">
        <p className="eyebrow">Primeiros passos</p>
        <h1 className="text-4xl font-semibold leading-[1.05] tracking-[-0.03em] text-[var(--foreground-strong)]">
          Vamos conectar o console ao gateway
        </h1>
        <p className="max-w-xl text-sm leading-7 text-[var(--muted-foreground)]">
          O seclab não tem cadastro pela web de propósito (evita o problema de "quem pode criar o
          primeiro usuário"). O primeiro usuário e sua API key vêm da CLI, rodada uma vez na
          máquina que já tem acesso ao código.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>1. Gere sua API key</CardTitle>
          <CardDescription>
            No terminal, na raiz do repositório (com a venv do projeto ativa):
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-2">
          <pre className="subpanel overflow-x-auto p-3 text-sm text-[var(--foreground)]">
            <code>{INIT_COMMAND}</code>
          </pre>
          <p className="text-xs leading-6 text-[var(--muted-foreground)]">
            Isso gera o segredo interno do gateway, cria o banco local e imprime uma API key -
            copie-a, ela só aparece uma vez. Se você já rodou isso antes, use{" "}
            <code className="font-mono">{USERS_COMMAND}</code> para criar mais uma.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>2. Cole a chave abaixo</CardTitle>
          <CardDescription>Fica salva só no seu navegador (localStorage), nunca é enviada a mais nada.</CardDescription>
        </CardHeader>
        <CardContent>
          <ApiKeyForm onSaved={() => refetch()} />
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>3. Testar conexão</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <Button type="button" onClick={() => refetch()}>
            Testar conexão
          </Button>
          {status === "checking" || status === "invalid_key" || status === "unreachable" ? (
            <StatusMessage status={status} />
          ) : null}
          {status === "connected" ? (
            <p className="text-sm leading-6 text-[var(--success)]">
              Conectado! Redirecionando para o painel...
            </p>
          ) : null}
        </CardContent>
      </Card>
    </div>
  );
}
