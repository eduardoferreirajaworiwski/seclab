import Link from "next/link";

import { PageHeader } from "@/components/shared/page-header";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";

const MODULES: {
  name: string;
  track: "Descoberta" | "Bug bounty" | "Intel";
  summary: string;
}[] = [
  {
    name: "Phantom",
    track: "Descoberta",
    summary:
      "Detecta domínios lookalike/typosquat a partir de Certificate Transparency, com scoring de risco e (quando configurado) um resumo gerado por IA.",
  },
  {
    name: "Monitor",
    track: "Descoberta",
    summary:
      "Stream em tempo real de Certificate Transparency, cruzado com o mesmo scoring do Phantom.",
  },
  {
    name: "Recon",
    track: "Bug bounty",
    summary:
      "O workflow principal: Programa → Target (checado contra o escopo) → Hipótese → Aprovação humana obrigatória → Execução → Finding. Também expõe o mapeamento de superfície de ataque (attack_surface) por target.",
  },
  {
    name: "Aprovações",
    track: "Bug bounty",
    summary:
      "Fila de decisão humana: toda hipótese de recon precisa de aprovação de alguém com papel suficiente antes de qualquer execução ser enfileirada.",
  },
  {
    name: "Intel",
    track: "Intel",
    summary:
      "ThreatLens (digest semanal de notícias de segurança, tagueamento determinístico de vetor de ataque) e CVE Watch (rastreamento de CVE/CISA-KEV), lado a lado.",
  },
  {
    name: "Fusion",
    track: "Intel",
    summary:
      "Feed somente-leitura que correlaciona Monitor + ThreatLens + CVE Watch - não tem persistência própria.",
  },
];

export default function DocsPage() {
  return (
    <div className="space-y-8">
      <PageHeader
        title="Como funciona"
        description="Arquitetura, módulos e autenticação do seclab, em um só lugar - sem precisar ler o código."
      />

      <Card>
        <CardHeader>
          <CardTitle>Arquitetura em 1 minuto</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm leading-7 text-[var(--muted-foreground)]">
          <p>
            Um único processo de gateway (FastAPI) monta cada módulo interno sob{" "}
            <code className="font-mono text-[var(--foreground)]">/api/v1/&lt;módulo&gt;</code>.
            Este site (Next.js) é só um cliente HTTP desse gateway - toda lógica de negócio, todo
            dado, vive no backend.
          </p>
          <p>
            Por padrão os dados ficam num arquivo SQLite local (
            <code className="font-mono text-[var(--foreground)]">seclab.db</code>), sem depender
            de nenhum serviço externo. IA (Gemini/OpenAI) é opcional e só é usada para gerar
            resumos/sugestões - o comportamento determinístico sempre funciona como alternativa se
            a IA estiver desligada ou falhar.
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>O que cada módulo faz</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          {(["Descoberta", "Bug bounty", "Intel"] as const).map((track) => (
            <div key={track} className="space-y-2">
              <p className="text-xs font-semibold uppercase tracking-[0.14em] text-[var(--muted-foreground)]">
                {track}
              </p>
              <div className="grid gap-3 md:grid-cols-2">
                {MODULES.filter((m) => m.track === track).map((mod) => (
                  <div key={mod.name} className="subpanel space-y-1 p-4">
                    <p className="text-sm font-semibold text-[var(--foreground-strong)]">{mod.name}</p>
                    <p className="text-xs leading-6 text-[var(--muted-foreground)]">{mod.summary}</p>
                  </div>
                ))}
              </div>
            </div>
          ))}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Autenticação em 1 minuto</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3 text-sm leading-7 text-[var(--muted-foreground)]">
          <p>
            Não existe cadastro pela web. Todo usuário é criado pela CLI (
            <code className="font-mono text-[var(--foreground)]">seclab init</code> para o
            primeiro,{" "}
            <code className="font-mono text-[var(--foreground)]">seclab users create</code> para
            os seguintes) - a chave (API key) é impressa uma única vez e deve ser colada aqui no
            site.
          </p>
          <p>
            Cada requisição autenticada leva{" "}
            <code className="font-mono text-[var(--foreground)]">Authorization: Bearer
            &lt;chave&gt;</code>. Existem dois papéis (RBAC): <code className="font-mono">analyst</code> e{" "}
            <code className="font-mono">security_lead</code> - hipóteses de recon podem exigir um
            papel mínimo para serem aprovadas.
          </p>
          <p>
            Sem chave salva, ou com o gateway fora do ar, o site te leva para a tela de{" "}
            <Link href="/onboarding" className="underline">
              primeiros passos
            </Link>
            .
          </p>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Como chamar a API diretamente</CardTitle>
          <CardDescription>Útil para scripts, automações, ou só para inspecionar uma resposta crua.</CardDescription>
        </CardHeader>
        <CardContent>
          <pre className="subpanel overflow-x-auto p-3 text-sm text-[var(--foreground)]">
            <code>{`curl -H "Authorization: Bearer $SECLAB_API_KEY" \\
  http://127.0.0.1:8000/api/v1/health`}</code>
          </pre>
        </CardContent>
      </Card>
    </div>
  );
}
