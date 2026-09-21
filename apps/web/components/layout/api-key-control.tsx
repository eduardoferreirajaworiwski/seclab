"use client";

import { useEffect, useState } from "react";

import { ApiKeyForm } from "@/components/shared/api-key-form";
import { Button } from "@/components/ui/button";
import { getStoredApiKey } from "@/lib/api/auth";

export function ApiKeyControl() {
  const [open, setOpen] = useState(false);
  const [hasKey, setHasKey] = useState(false);

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
    <ApiKeyForm
      onSaved={() => {
        setHasKey(Boolean(getStoredApiKey()));
        setOpen(false);
      }}
    />
  );
}
