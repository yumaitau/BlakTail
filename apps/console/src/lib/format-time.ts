/**
 * UTC date and time text built by hand, so it is identical on the server and
 * in the browser. People see times through `<LocalTime>` (viewer's time zone);
 * these give its first render and its UTC hover text, and suit places that
 * need one plain string (exports, aria labels).
 */

const MONTHS = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];

/** Unix seconds, an ISO string or a Date. */
export type TimeInput = number | string | Date | null | undefined;

export function toDate(value: TimeInput): Date | null {
  if (value === null || value === undefined || value === "" || value === 0) return null;
  const date =
    value instanceof Date ? value : typeof value === "number" ? new Date(value * 1000) : new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

/** "5 Oct 2026" (UTC). */
export function formatDate(value: TimeInput, empty = "—"): string {
  const date = toDate(value);
  if (!date) return empty;
  return `${date.getUTCDate()} ${MONTHS[date.getUTCMonth()]} ${date.getUTCFullYear()}`;
}

/** "5 Oct 2026, 14:07 UTC". */
export function formatDateTime(value: TimeInput, empty = "—"): string {
  const date = toDate(value);
  if (!date) return empty;
  const hours = String(date.getUTCHours()).padStart(2, "0");
  const minutes = String(date.getUTCMinutes()).padStart(2, "0");
  return `${formatDate(date)}, ${hours}:${minutes} UTC`;
}
