import * as React from "react";

import { cn } from "@/lib/utils";

const Input = React.forwardRef<HTMLInputElement, React.ComponentProps<"input">>(({ className, ...props }, ref) => {
  return (
    <input
      ref={ref}
      className={cn(
        "flex h-11 w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-inset)] px-4 text-sm text-[var(--foreground)] outline-none transition-colors placeholder:text-[var(--subtle-foreground)] focus:border-[var(--border-accent)] focus:bg-[var(--surface-hover)] focus:ring-2 focus:ring-[var(--focus-ring)] disabled:cursor-not-allowed disabled:opacity-55",
        className,
      )}
      {...props}
    />
  );
});
Input.displayName = "Input";

export { Input };
