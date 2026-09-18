"use client";

import { useQueryClient } from "@tanstack/react-query";
import { useEffect, useState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { getStoredApiKey, setStoredApiKey } from "@/lib/api/auth";

export function ApiKeyControl() {
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState("");
  const [hasKey, setHasKey] = useState(false);
  const queryClient = useQueryClient();

  useEffect(() => {
    setHasKey(Boolean(getStoredApiKey()));
  }, []);

  if (!open) {
    return (
      <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
        {hasKey ? "API key set" : "Set API key"}
      </Button>
    );
  }

  return (
    <form
      className="flex flex-wrap items-center gap-2"
      onSubmit={(event) => {
        event.preventDefault();
        setStoredApiKey(value.trim() || null);
        setHasKey(Boolean(value.trim()));
        setValue("");
        setOpen(false);
        // Every query that already ran (and every 401 it hit before a key
        // was set, or before this new key) is sitting on stale
        // data/error - without this, the rest of the dashboard stays
        // broken until the user manually reloads the page. Invalidating
        // everything forces an immediate refetch with the new
        // Authorization header.
        queryClient.invalidateQueries();
      }}
    >
      <Input
        type="password"
        value={value}
        onChange={(event) => setValue(event.target.value)}
        placeholder="Paste your API key"
        className="h-9 w-56"
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
          setHasKey(false);
          setValue("");
          setOpen(false);
          queryClient.invalidateQueries();
        }}
      >
        Clear
      </Button>
    </form>
  );
}
