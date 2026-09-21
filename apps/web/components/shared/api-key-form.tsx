"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { setStoredApiKey } from "@/lib/api/auth";

/**
 * Shared "paste your API key" form, used both by the topbar's compact
 * ApiKeyControl and by the full-screen onboarding flow. Extracted so the
 * save/clear/invalidate logic lives in exactly one place.
 */
export function ApiKeyForm({ onSaved }: { onSaved?: () => void }) {
  const [value, setValue] = useState("");
  const queryClient = useQueryClient();

  return (
    <form
      className="flex flex-wrap items-center gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        setStoredApiKey(value.trim() || null);
        setValue("");
        // Every query that already ran (and every 401 it hit before a key
        // was set, or before this new key) is sitting on stale
        // data/error - without this, the rest of the dashboard stays
        // broken until the user manually reloads the page. Invalidating
        // everything forces an immediate refetch with the new
        // Authorization header.
        queryClient.invalidateQueries();
        onSaved?.();
      }}
    >
      <Input
        type="password"
        value={value}
        onChange={(event) => setValue(event.target.value)}
        placeholder="Paste your API key"
        className="h-9 w-64"
        autoFocus
      />
      <Button type="submit" size="sm">
        Save
      </Button>
      <Button
        type="button"
        variant="secondary"
        size="sm"
        onClick={() => {
          setStoredApiKey(null);
          setValue("");
          queryClient.invalidateQueries();
          onSaved?.();
        }}
      >
        Clear
      </Button>
    </form>
  );
}
