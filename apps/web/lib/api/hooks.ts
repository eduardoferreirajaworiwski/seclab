import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";

import { apiClient } from "@/lib/api/client";
import type {
  AnalysisListResponse,
  AnalysisResult,
  ApprovalDecisionPayload,
  ApprovalRead,
  BreachCheckListResponse,
  BreachCheckResult,
  CompleteExecutionPayload,
  CreateAnalysisPayload,
  CreateBreachCheckPayload,
  CreateCveDigestPayload,
  CreateDigestPayload,
  CreateHypothesisPayload,
  CreateProgramPayload,
  CreateSurfaceScanPayload,
  CreateTargetPayload,
  CveDigestListResponse,
  CveDigestResult,
  DigestListResponse,
  DigestResult,
  ExecutionRead,
  FindingRead,
  FusionFeedResponse,
  HealthResponse,
  HypothesisRead,
  MonitorMatch,
  ProgramRead,
  QueueExecutionPayload,
  RequestApprovalPayload,
  SurfaceScanListResponse,
  SurfaceScanResult,
  TargetRead,
} from "@/lib/types/api";

// --- health ---

export function useHealthQuery() {
  return useQuery({
    queryKey: ["health"],
    queryFn: () => apiClient.get<HealthResponse>("/health"),
  });
}

// --- phantom ---

export function useAnalysesQuery(limit = 10) {
  return useQuery({
    queryKey: ["phantom", "analyses", limit],
    queryFn: () => apiClient.get<AnalysisListResponse>(`/phantom/analyses?limit=${limit}`),
  });
}

export function useAnalysisQuery(analysisId: string | null) {
  return useQuery({
    queryKey: ["phantom", "analysis", analysisId],
    queryFn: () => apiClient.get<AnalysisResult>(`/phantom/analyses/${analysisId}`),
    enabled: Boolean(analysisId),
  });
}

export function useCreateAnalysisMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateAnalysisPayload) =>
      apiClient.post<AnalysisResult>("/phantom/analyses", payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["phantom", "analyses"] }),
  });
}

// --- monitor ---

export function useMonitorMatchesQuery(limit = 20) {
  return useQuery({
    queryKey: ["monitor", "matches", limit],
    queryFn: () => apiClient.get<MonitorMatch[]>(`/monitor/matches?limit=${limit}`),
  });
}

// --- recon: programs ---

export function useProgramsQuery() {
  return useQuery({
    queryKey: ["recon", "programs"],
    queryFn: () => apiClient.get<ProgramRead[]>("/recon/programs"),
  });
}

export function useProgramQuery(programId: number) {
  return useQuery({
    queryKey: ["recon", "program", programId],
    queryFn: () => apiClient.get<ProgramRead>(`/recon/programs/${programId}`),
    enabled: Number.isFinite(programId),
  });
}

export function useCreateProgramMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateProgramPayload) =>
      apiClient.post<ProgramRead>("/recon/programs", payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["recon", "programs"] }),
  });
}

// --- recon: targets ---

export function useProgramTargetsQuery(programId: number) {
  return useQuery({
    queryKey: ["recon", "program", programId, "targets"],
    queryFn: () => apiClient.get<TargetRead[]>(`/recon/programs/${programId}/targets`),
    enabled: Number.isFinite(programId),
  });
}

export function useCreateTargetMutation(programId: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateTargetPayload) =>
      apiClient.post<TargetRead>(`/recon/programs/${programId}/targets`, payload),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["recon", "program", programId, "targets"] }),
  });
}

// --- recon: hypotheses ---

export function useProgramHypothesesQuery(programId: number) {
  return useQuery({
    queryKey: ["recon", "program", programId, "hypotheses"],
    queryFn: () => apiClient.get<HypothesisRead[]>(`/recon/programs/${programId}/hypotheses`),
    enabled: Number.isFinite(programId),
  });
}

export function useCreateHypothesisMutation(programId: number, targetId: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateHypothesisPayload) =>
      apiClient.post<HypothesisRead>(`/recon/targets/${targetId}/hypotheses`, payload),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["recon", "program", programId, "hypotheses"] }),
  });
}

// --- recon: executions ---

export function useHypothesisExecutionsQuery(hypothesisId: number) {
  return useQuery({
    queryKey: ["recon", "hypothesis", hypothesisId, "executions"],
    queryFn: () =>
      apiClient.get<ExecutionRead[]>(`/recon/hypotheses/${hypothesisId}/executions`),
    enabled: Number.isFinite(hypothesisId),
  });
}

export function useQueueExecutionMutation(hypothesisId: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: QueueExecutionPayload) =>
      apiClient.post<ExecutionRead>(`/recon/hypotheses/${hypothesisId}/executions`, payload),
    onSuccess: () =>
      queryClient.invalidateQueries({
        queryKey: ["recon", "hypothesis", hypothesisId, "executions"],
      }),
  });
}

export function useCompleteExecutionMutation(
  executionId: number,
  hypothesisId: number,
  programId: number,
) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CompleteExecutionPayload) =>
      apiClient.post<FindingRead>(`/recon/executions/${executionId}/complete`, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({
        queryKey: ["recon", "hypothesis", hypothesisId, "executions"],
      });
      queryClient.invalidateQueries({
        queryKey: ["recon", "program", programId, "findings"],
      });
    },
  });
}

// --- recon: findings ---

export function useProgramFindingsQuery(programId: number) {
  return useQuery({
    queryKey: ["recon", "program", programId, "findings"],
    queryFn: () => apiClient.get<FindingRead[]>(`/recon/programs/${programId}/findings`),
    enabled: Number.isFinite(programId),
  });
}

// --- recon: approvals ---

export function usePendingApprovalsQuery() {
  return useQuery({
    queryKey: ["recon", "approvals", "pending"],
    queryFn: () => apiClient.get<ApprovalRead[]>("/recon/approvals/pending"),
  });
}

export function useRequestApprovalMutation(hypothesisId: number, programId: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: RequestApprovalPayload) =>
      apiClient.post<ApprovalRead>(`/recon/hypotheses/${hypothesisId}/approval-requests`, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["recon", "approvals", "pending"] });
      queryClient.invalidateQueries({ queryKey: ["recon", "program", programId, "hypotheses"] });
    },
  });
}

export function useApproveApprovalMutation(approvalId: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ApprovalDecisionPayload) =>
      apiClient.post<ApprovalRead>(`/recon/approvals/${approvalId}/approve`, payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["recon", "approvals", "pending"] }),
  });
}

export function useRejectApprovalMutation(approvalId: number) {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: ApprovalDecisionPayload) =>
      apiClient.post<ApprovalRead>(`/recon/approvals/${approvalId}/reject`, payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["recon", "approvals", "pending"] }),
  });
}

// --- threatlens ---

export function useThreatLensDigestsQuery(limit = 10) {
  return useQuery({
    queryKey: ["threatlens", "digests", limit],
    queryFn: () => apiClient.get<DigestListResponse>(`/threatlens/digests?limit=${limit}`),
  });
}

export function useThreatLensDigestQuery(digestId: string | null) {
  return useQuery({
    queryKey: ["threatlens", "digest", digestId],
    queryFn: () => apiClient.get<DigestResult>(`/threatlens/digests/${digestId}`),
    enabled: Boolean(digestId),
  });
}

export function useCreateThreatLensDigestMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateDigestPayload = {}) =>
      apiClient.post<DigestResult>("/threatlens/digests", payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["threatlens", "digests"] }),
  });
}

// --- cve_watch ---

export function useCveWatchDigestsQuery(limit = 10) {
  return useQuery({
    queryKey: ["cve_watch", "digests", limit],
    queryFn: () => apiClient.get<CveDigestListResponse>(`/cve_watch/digests?limit=${limit}`),
  });
}

export function useCveWatchDigestQuery(digestId: string | null) {
  return useQuery({
    queryKey: ["cve_watch", "digest", digestId],
    queryFn: () => apiClient.get<CveDigestResult>(`/cve_watch/digests/${digestId}`),
    enabled: Boolean(digestId),
  });
}

export function useCreateCveWatchDigestMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateCveDigestPayload = {}) =>
      apiClient.post<CveDigestResult>("/cve_watch/digests", payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["cve_watch", "digests"] }),
  });
}

// --- osint_breach ---

export function useBreachChecksQuery(limit = 10) {
  return useQuery({
    queryKey: ["osint_breach", "checks", limit],
    queryFn: () => apiClient.get<BreachCheckListResponse>(`/osint_breach/checks?limit=${limit}`),
  });
}

export function useBreachCheckQuery(checkId: string | null) {
  return useQuery({
    queryKey: ["osint_breach", "check", checkId],
    queryFn: () => apiClient.get<BreachCheckResult>(`/osint_breach/checks/${checkId}`),
    enabled: Boolean(checkId),
  });
}

export function useCreateBreachCheckMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateBreachCheckPayload) =>
      apiClient.post<BreachCheckResult>("/osint_breach/checks", payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["osint_breach", "checks"] }),
  });
}

// --- attack_surface ---

export function useSurfaceScansQuery(limit = 10) {
  return useQuery({
    queryKey: ["attack_surface", "scans", limit],
    queryFn: () => apiClient.get<SurfaceScanListResponse>(`/attack_surface/scans?limit=${limit}`),
  });
}

export function useSurfaceScanQuery(scanId: string | null) {
  return useQuery({
    queryKey: ["attack_surface", "scan", scanId],
    queryFn: () => apiClient.get<SurfaceScanResult>(`/attack_surface/scans/${scanId}`),
    enabled: Boolean(scanId),
  });
}

export function useCreateSurfaceScanMutation() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (payload: CreateSurfaceScanPayload) =>
      apiClient.post<SurfaceScanResult>("/attack_surface/scans", payload),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["attack_surface", "scans"] }),
  });
}

// --- fusion ---

export function useFusionFeedQuery(limit = 20) {
  return useQuery({
    queryKey: ["fusion", "feed", limit],
    queryFn: () => apiClient.get<FusionFeedResponse>(`/fusion/feed?limit=${limit}`),
  });
}
