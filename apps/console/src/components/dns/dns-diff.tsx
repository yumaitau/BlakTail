import type { DiffLine } from "@/lib/text-diff";

export function DnsDiff({ lines, label }: { lines: DiffLine[]; label: string }) {
  const changed = lines.some((line) => line.kind !== "same");
  return (
    <figure className="dns-diff" aria-label={label}>
      <figcaption className="muted">{label}</figcaption>
      {changed ? (
        <pre className="mono dns-pre">
          {lines.map((line, index) => (
            <span key={index} className={`dns-diff-${line.kind}`}>
              {line.kind === "added" ? "+ " : line.kind === "removed" ? "- " : "  "}
              {line.text}
              {"\n"}
            </span>
          ))}
        </pre>
      ) : (
        <p className="muted">No differences.</p>
      )}
    </figure>
  );
}
