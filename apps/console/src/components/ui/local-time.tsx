"use client";

import { useSyncExternalStore } from "react";
import { formatDate, formatDateTime, toDate, type TimeInput } from "@/lib/format-time";

const DATE_TIME = new Intl.DateTimeFormat("en-AU", {
  day: "numeric",
  month: "short",
  year: "numeric",
  hour: "numeric",
  minute: "2-digit",
  timeZoneName: "short",
});
const DATE_ONLY = new Intl.DateTimeFormat("en-AU", { day: "numeric", month: "short", year: "numeric" });

const noSubscription = () => () => {};

/** False while the server renders and during hydration, true afterwards. */
function useHydrated(): boolean {
  return useSyncExternalStore(
    noSubscription,
    () => true,
    () => false,
  );
}

/**
 * A time in the viewer's own time zone ("5 Oct 2026, 1:20 pm AEDT"), with the
 * exact UTC time on hover. The server and the first browser render show the
 * same UTC text, then the browser switches to local time, so there's never a
 * hydration mismatch. Takes Unix seconds, an ISO string or a Date.
 */
export function LocalTime({
  value,
  fallback = "Never",
  dateOnly = false,
  className,
}: {
  value: TimeInput;
  fallback?: string;
  dateOnly?: boolean;
  className?: string;
}) {
  const hydrated = useHydrated();
  const date = toDate(value);
  if (!date) return <>{fallback}</>;
  const utc = dateOnly ? formatDate(date) : formatDateTime(date);
  const text = hydrated ? (dateOnly ? DATE_ONLY : DATE_TIME).format(date) : utc;
  return (
    <time dateTime={date.toISOString()} title={formatDateTime(date)} className={className}>
      {text}
    </time>
  );
}
