import type { ReactNode } from "react";
import { CopyButton } from "./copy-button";

/**
 * A technical value (key, address, ID, FQDN) in monospace. Long values
 * truncate with the full text in `title`; `copy` adds a copy button.
 * `wrap` lets the value break across lines instead of truncating.
 */
export function MonoValue({
  value,
  copy = false,
  copyLabel,
  wrap = false,
  children,
}: {
  value: string;
  copy?: boolean;
  /** Accessible name for the copy button, e.g. "Copy public key". */
  copyLabel?: string;
  wrap?: boolean;
  /** Optional display text; `value` is still what is copied. */
  children?: ReactNode;
}) {
  return (
    <span className={wrap ? "mono-value wrap" : "mono-value"}>
      <span className="mono mono-value-text" title={value}>
        {children ?? value}
      </span>
      {copy ? <CopyButton value={value} label={copyLabel ?? `Copy ${value}`} /> : null}
    </span>
  );
}
