"use client";

import { useQuery } from "@tanstack/react-query";

import { getStoredApiKey } from "@/lib/api/auth";
import { apiClient, ApiError } from "@/lib/api/client";
import type { HealthResponse } from "@/lib/types/api";

export type ConnectionStatus = "no_key" | "connected" | "invalid_key" | "unreachable" | "checking";

/**
 * Determines whether the dashboard can talk to the gateway right now.
 *
 * Distinguishes three very different situations that all used to collapse
 * into the same small "API Unreachable" badge:
 *  - "no_key": first-time visitor, nothing saved yet - expected, not an error.
 *  - "invalid_key": a key is saved but the gateway rejected it (typo,
 *    revoked, wrong environment).
 *  - "unreachable": the gateway process itself isn't responding at all.
 * Each needs a different message in the onboarding screen (see
 * app/onboarding/page.tsx), so the distinction is made here once instead of
 * every consumer re-deriving it from an ApiError.
 */
export function useConnectionStatus(): { status: ConnectionStatus; refetch: () => void } {
  const hasKey = Boolean(getStoredApiKey());
  const health = useQuery({
    queryKey: ["connection-check"],
    queryFn: () => apiClient.get<HealthResponse>("/health"),
    enabled: hasKey,
    retry: false,
  });

  if (!hasKey) {
    return { status: "no_key", refetch: () => health.refetch() };
  }
  if (health.isPending) {
    return { status: "checking", refetch: () => health.refetch() };
  }
  if (health.isError) {
    const status: ConnectionStatus =
      health.error instanceof ApiError && health.error.status === 401
        ? "invalid_key"
        : "unreachable";
    return { status, refetch: () => health.refetch() };
  }
  return { status: "connected", refetch: () => health.refetch() };
}
