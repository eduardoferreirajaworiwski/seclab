// --- shared ---
export interface HealthResponse {
  status: string;
  version: string;
  environment: string;
  offline_mode: boolean;
  modules: string[];
}

// --- phantom ---
export type TargetType = "brand" | "domain";

export interface AnalysisListItem {
  analysis_id: string;
  created_at: string;
  target: string;
  high_priority_count: number;
  medium_priority_count: number;
  total_assets: number;
  summary_headline: string;
  offline_mode: boolean;
}
export interface AnalysisListResponse {
  analyses: AnalysisListItem[];
}
export interface AnalysisResult {
  analysis_id: string;
  created_at: string;
  report_markdown: string;
  [key: string]: unknown;
}
export interface CreateAnalysisPayload {
  target: string;
  target_type: TargetType;
  max_variants: number;
  offline_mode: boolean;
}

// --- monitor ---
export interface MonitorMatch {
  id: number;
  domain: string;
  matched_keyword: string;
  issuer: string;
  score: number;
  priority: string;
  capture_status: string;
  created_at: string;
}

// --- recon ---
export interface ScopePolicy {
  allowed_domains?: string[];
  denied_domains?: string[];
}
export interface ProgramRead {
  id: number;
  name: string;
  description: string;
  owner: string;
  scope_policy: ScopePolicy;
  created_at: string;
}
export interface CreateProgramPayload {
  name: string;
  description: string;
  scope_policy: ScopePolicy;
}
export interface TargetRead {
  id: number;
  program_id: number;
  identifier: string;
  target_type: string;
  created_by: string;
  in_scope: boolean;
  scope_reason: string;
  created_at: string;
}
export interface CreateTargetPayload {
  identifier: string;
  target_type: string;
}
export interface HypothesisRead {
  id: number;
  program_id: number;
  target_id: number;
  title: string;
  description: string;
  confidence: number;
  suggested_next_step: string;
  required_role: string;
  severity: string;
  created_by: string;
  status: string;
  created_at: string;
  updated_at: string;
}
export interface CreateHypothesisPayload {
  title: string;
  description: string;
}
export interface ExecutionRead {
  id: number;
  hypothesis_id: number;
  requested_by: string;
  approved_by: string | null;
  status: string;
  action_plan: string;
  output_summary: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}
export interface QueueExecutionPayload {
  action_plan: string;
}
export interface CompleteExecutionPayload {
  output_summary: string;
  finding_title: string;
  finding_description: string;
  finding_severity: string;
}
export interface FindingRead {
  id: number;
  program_id: number;
  target_id: number;
  hypothesis_id: number;
  execution_id: number;
  title: string;
  description: string;
  severity: string;
  status: string;
  created_at: string;
}
export interface ApprovalRead {
  id: number;
  subject_type: string;
  subject_id: string;
  required_role: string;
  requested_by: string;
  request_rationale: string;
  approver: string | null;
  approver_role: string | null;
  status: string;
  decision_reason: string | null;
  created_at: string;
  expires_at: string | null;
  decided_at: string | null;
}
export interface ApprovalDecisionPayload {
  rationale: string;
}
export interface RequestApprovalPayload {
  rationale: string;
  expires_in_minutes?: number | null;
}

// --- threatlens ---
export type AttackVector =
  | "ransomware"
  | "phishing"
  | "zero_day"
  | "supply_chain"
  | "remote_code_execution"
  | "ddos"
  | "data_breach"
  | "credential_attack"
  | "malware"
  | "cloud_misconfiguration";

export interface RiskSignal {
  name: string;
  weight: number;
  detail: string;
  [key: string]: unknown;
}

export interface ThreatArticle {
  title: string;
  link: string;
  published_at: string;
  source: string;
  summary: string;
  vectors: AttackVector[];
  vector_signals: RiskSignal[];
}

export interface DigestSummary {
  headline: string;
  executive_summary: string;
  vector_breakdown: string[];
  notable_incidents: string[];
  recommended_actions: string[];
  grounding_notes: string[];
  model_source: string;
}

export interface DigestResult {
  digest_id: string;
  created_at: string;
  lookback_days: number;
  articles: ThreatArticle[];
  summary: DigestSummary;
  report_markdown: string;
  metadata: Record<string, unknown>;
}

export interface DigestListItem {
  digest_id: string;
  created_at: string;
  article_count: number;
  top_vectors: string[];
  summary_headline: string;
  offline_mode: boolean;
}

export interface DigestListResponse {
  digests: DigestListItem[];
}

export interface CreateDigestPayload {
  lookback_days?: number;
  max_articles_per_feed?: number;
  offline_mode?: boolean;
}
