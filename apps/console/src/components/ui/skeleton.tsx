/**
 * Loading placeholders shaped like the content they stand in for. Use in
 * `loading.tsx` files and while client data loads; never a spinner in the
 * middle of a page. Announced once as "Loading" to screen readers.
 */
export function Skeleton({
  lines = 3,
  label = "Loading",
}: {
  lines?: number;
  label?: string;
}) {
  return (
    <div className="skeleton" role="status" aria-busy="true">
      <span className="visually-hidden">{label}</span>
      {Array.from({ length: lines }, (_, index) => (
        <div
          key={index}
          className="skeleton-line"
          aria-hidden="true"
          style={{ width: index === lines - 1 ? "60%" : "100%" }}
        />
      ))}
    </div>
  );
}

/** A table-shaped placeholder: a header bar and `rows` rows. */
export function SkeletonTable({ rows = 5, label = "Loading" }: { rows?: number; label?: string }) {
  return (
    <div className="skeleton skeleton-table" role="status" aria-busy="true">
      <span className="visually-hidden">{label}</span>
      <div className="skeleton-line skeleton-head" aria-hidden="true" />
      {Array.from({ length: rows }, (_, index) => (
        <div key={index} className="skeleton-row" aria-hidden="true">
          <div className="skeleton-line" />
          <div className="skeleton-line" />
          <div className="skeleton-line" />
        </div>
      ))}
    </div>
  );
}

/** Page-level placeholder for `loading.tsx`: header, summary and a table. */
export function SkeletonPage() {
  return (
    <div className="stack" aria-busy="true">
      <div className="skeleton skeleton-header" aria-hidden="true">
        <div className="skeleton-line" style={{ width: "6rem" }} />
        <div className="skeleton-line skeleton-title" style={{ width: "14rem" }} />
        <div className="skeleton-line" style={{ width: "min(32rem, 90%)" }} />
      </div>
      <div className="panel">
        <SkeletonTable rows={6} label="Loading page" />
      </div>
    </div>
  );
}
