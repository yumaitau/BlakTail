import type { ReactNode } from "react";
import { Lock } from "lucide-react";

/**
 * Explains why the signed-in person can see but not change something.
 * `reason` should name the role that can ("Only owners and admins can …").
 * Server permission checks still apply; this is only the explanation.
 */
export function PermissionNotice({
  reason,
  children,
}: {
  reason: string;
  /** Optional next step, e.g. who to ask or what they can still do. */
  children?: ReactNode;
}) {
  return (
    <div className="ui-alert ui-alert-info permission-notice" role="status">
      <Lock className="ui-alert-icon" aria-hidden="true" size={16} />
      <div className="ui-alert-body">
        <p className="ui-alert-title">View only</p>
        <div className="ui-alert-text">
          {reason}
          {children ? <> {children}</> : null}
        </div>
      </div>
    </div>
  );
}
