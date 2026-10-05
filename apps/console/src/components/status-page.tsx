import type { ReactNode } from "react";
import { PathMotif } from "./path-motif";
import { Wordmark } from "./wordmark";

/** Shared body for the 404, error and global-error pages. */
export function StatusPage({
  code,
  title,
  body,
  reference,
  actions,
}: {
  code: string;
  title: string;
  body: ReactNode;
  reference?: string;
  actions: ReactNode;
}) {
  return (
    <main className="status-page" id="main">
      <div className="status-card">
        <Wordmark />
        <PathMotif />
        <p className="status-code">{code}</p>
        <h1>{title}</h1>
        <p className="muted">{body}</p>
        {reference ? <p className="ui-ref">Reference {reference}</p> : null}
        <div className="actions">{actions}</div>
      </div>
    </main>
  );
}
