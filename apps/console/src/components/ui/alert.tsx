import type { ReactNode } from "react";
import { AlertCircle, AlertTriangle, CheckCircle2, Info } from "lucide-react";

export type Tone = "info" | "success" | "warning" | "error";

const ICONS = {
  info: Info,
  success: CheckCircle2,
  warning: AlertTriangle,
  error: AlertCircle,
} as const;

/**
 * Inline message inside a page or form: load failures, form-level errors,
 * warnings. Errors use role="alert"; the rest are polite status. Pass the
 * error reference as `reference` so people can quote it to support.
 */
export function Alert({
  tone = "info",
  title,
  reference,
  action,
  children,
}: {
  tone?: Tone;
  title?: string;
  reference?: string;
  action?: ReactNode;
  children?: ReactNode;
}) {
  const Icon = ICONS[tone];
  return (
    <div className={`ui-alert ui-alert-${tone}`} role={tone === "error" ? "alert" : "status"}>
      <Icon className="ui-alert-icon" aria-hidden="true" size={18} />
      <div className="ui-alert-body">
        {title ? <p className="ui-alert-title">{title}</p> : null}
        {children ? <div className="ui-alert-text">{children}</div> : null}
        {reference ? <p className="ui-ref">Reference {reference}</p> : null}
      </div>
      {action ? <div className="ui-alert-action">{action}</div> : null}
    </div>
  );
}
