import type { ReactNode } from "react";
import { PathMotif } from "./path-motif";

/**
 * Shown when a list has nothing in it yet. Say what will appear here and how
 * to add the first one; put the action button in `action`. For "no search
 * results" inside a table use <EmptyRow> instead; for a failed load use
 * <Alert tone="error">, never an empty state.
 */
export function EmptyState({
  title,
  body,
  action,
  compact = false,
  headingLevel = 2,
}: {
  title: string;
  body: ReactNode;
  action?: ReactNode;
  compact?: boolean;
  headingLevel?: 2 | 3;
}) {
  const Heading = headingLevel === 2 ? "h2" : "h3";
  return (
    <div className={compact ? "empty-state compact" : "empty-state"}>
      {compact ? null : <PathMotif />}
      <Heading>{title}</Heading>
      <p className="muted">{body}</p>
      {action ? <div className="actions">{action}</div> : null}
    </div>
  );
}
