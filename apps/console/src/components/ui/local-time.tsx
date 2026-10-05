/**
 * A Unix time (seconds) in the viewer's locale and time zone. The server and
 * the browser can format it differently (different zones), so hydration
 * keeps the browser's text instead of warning.
 */
export function LocalTime({
  value,
  fallback = "Never",
  dateOnly = false,
}: {
  value: number | null | undefined;
  fallback?: string;
  dateOnly?: boolean;
}) {
  if (!value) return <>{fallback}</>;
  const date = new Date(value * 1000);
  return (
    <time dateTime={date.toISOString()} suppressHydrationWarning>
      {date.toLocaleString(
        "en-AU",
        dateOnly ? { dateStyle: "medium" } : { dateStyle: "medium", timeStyle: "short" },
      )}
    </time>
  );
}
