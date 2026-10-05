import type { ReactNode } from "react";

export type BadgeTone = "neutral" | "success" | "warning" | "danger" | "info" | "brand" | "muted";

// Reuses the existing `.badge` colour classes so old and new badges match.
const TONE_CLASS: Record<BadgeTone, string> = {
  neutral: "",
  success: "online",
  warning: "pending",
  danger: "warn",
  info: "info",
  brand: "network",
  muted: "offline",
};

/**
 * Small label for status or category. The dot is decorative: the text always
 * carries the meaning, so colour is never the only signal.
 */
export function Badge({
  tone = "neutral",
  dot = true,
  title,
  children,
}: {
  tone?: BadgeTone;
  dot?: boolean;
  title?: string;
  children: ReactNode;
}) {
  const classes = ["badge", TONE_CLASS[tone], dot ? "" : "no-dot"].filter(Boolean).join(" ");
  return (
    <span className={classes} title={title}>
      {children}
    </span>
  );
}

/** Alias for status columns: `<StatusPill tone="success">Online</StatusPill>`. */
export const StatusPill = Badge;
