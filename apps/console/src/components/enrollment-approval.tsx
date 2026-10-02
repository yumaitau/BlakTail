"use client";

import { useState, useTransition } from "react";
import { approveDeviceAuthorizationAction } from "@/app/actions";
import { can, type OrgRole } from "@/lib/roles";

export function EnrollmentApproval({
  code,
  role,
  alreadyApproved,
}: {
  code: string;
  role: OrgRole;
  alreadyApproved: boolean;
}) {
  const [approved, setApproved] = useState(alreadyApproved);
  const [message, setMessage] = useState<string | null>(null);
  const [pending, startTransition] = useTransition();
  const canAssignTags = can(role, "manage_peers");

  if (approved) {
    return (
      <div className="stack" role="status">
        <p>
          Device approved. Return to the terminal; enrollment will continue
          automatically.
        </p>
        <p className="muted">
          You can close this page. The short-lived grant works only for the
          device identity shown above.
        </p>
      </div>
    );
  }

  return (
    <form
      className="stack"
      onSubmit={(event) => {
        event.preventDefault();
        const formData = new FormData(event.currentTarget);
        setMessage(null);
        startTransition(async () => {
          const result = await approveDeviceAuthorizationAction(formData);
          if (!result.ok) {
            setMessage(result.error);
            return;
          }
          setApproved(true);
          setMessage(null);
        });
      }}
    >
      <input type="hidden" name="code" value={code} />
      {canAssignTags ? (
        <fieldset className="stack">
          <legend>Device tags</legend>
          <label>
            <input type="checkbox" name="tags" value="office" /> Office
          </label>
          <label>
            <input type="checkbox" name="tags" value="ranger" /> Ranger
          </label>
          <label>
            <input type="checkbox" name="tags" value="store" /> Store
          </label>
        </fieldset>
      ) : (
        <p className="muted">
          Member enrollments start without privileged device tags.
        </p>
      )}
      {message ? (
        <p className="error" role="alert">
          {message}
        </p>
      ) : null}
      <button type="submit" disabled={pending}>
        {pending ? "Approving…" : "Approve this device"}
      </button>
    </form>
  );
}
