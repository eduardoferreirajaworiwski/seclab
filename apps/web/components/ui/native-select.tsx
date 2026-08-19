import * as React from "react";

import { cn } from "@/lib/utils";

const NativeSelect = React.forwardRef<HTMLSelectElement, React.ComponentProps<"select">>(
  ({ className, ...props }, ref) => {
    return (
      <select
        ref={ref}
        className={cn(
          "flex h-11 w-full rounded-md border border-[var(--border-subtle)] bg-[var(--surface-inset)] px-4 text-sm text-[var(--foreground)] outline-none transition-colors focus:border-[var(--border-accent)] focus:bg-[var(--surface-hover)] focus:ring-2 focus:ring-[var(--focus-ring)] disabled:cursor-not-allowed disabled:opacity-55 [&_option]:bg-[var(--surface-strong)] [&_option]:text-[var(--foreground)]",
          className,
        )}
        {...props}
      />
    );
  },
);
NativeSelect.displayName = "NativeSelect";

export { NativeSelect };
