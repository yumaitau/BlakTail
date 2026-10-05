"use client";

import { Check, Copy } from "lucide-react";
import { useEffect, useState } from "react";
import { toast } from "./toast";

/**
 * Small icon button that copies `value` to the clipboard. `label` names what
 * is copied ("Copy public key"); the result is announced with a toast.
 */
export function CopyButton({
  value,
  label,
  toastMessage,
}: {
  value: string;
  label: string;
  /** Success toast text. Defaults to "Copied". */
  toastMessage?: string;
}) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const timer = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(timer);
  }, [copied]);
  return (
    <button
      type="button"
      className="icon-button copy-button"
      aria-label={label}
      title={label}
      onClick={() => {
        if (!navigator.clipboard) {
          toast.error("Couldn't copy. Select the text and copy it manually.");
          return;
        }
        void navigator.clipboard.writeText(value).then(
          () => {
            setCopied(true);
            toast.success(toastMessage ?? "Copied");
          },
          () => toast.error("Couldn't copy. Select the text and copy it manually."),
        );
      }}
    >
      {copied ? <Check aria-hidden="true" size={14} /> : <Copy aria-hidden="true" size={14} />}
    </button>
  );
}
