"use client";

import { useState, useTransition } from "react";
import { approveDeviceAuthorizationAction } from "@/app/actions";
import { can, type OrgRole } from "@/lib/roles";
import { Alert } from "./ui/alert";
import { Button } from "./ui/button";
import { toast, toastResult } from "./ui/toast";

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
  const [pending, startTransition] = useTransition();
  const canAssignTags = can(role, "manage_peers");

  if (approved) {
    return (
      <Alert tone="success" title="Device approved">
        Return to the terminal; enrolment continues automatically. You can close this page. The
        short-lived grant works only for the device identity shown above.
      </Alert>
    );
  }

  return (
    <form
      className="ui-form"
      onSubmit={(event) => {
        event.preventDefault();
        const formData = new FormData(event.currentTarget);
        startTransition(async () => {
          const result = await approveDeviceAuthorizationAction(formData);
          toastResult(result);
          if (!result.ok) return;
          toast.success("Device approved", {
            description: "Enrolment continues in the terminal.",
          });
          setApproved(true);
        });
      }}
    >
      <input type="hidden" name="code" value={code} />
      {canAssignTags ? (
        <fieldset className="ui-fieldset">
          <legend>Device tags</legend>
          <div className="ui-choices">
            <label>
              <input type="checkbox" name="tags" value="office" /> Office
            </label>
            <label>
              <input type="checkbox" name="tags" value="ranger" /> Ranger
            </label>
            <label>
              <input type="checkbox" name="tags" value="store" /> Store
            </label>
          </div>
          <p className="ui-field-hint">Tags decide which access rules apply to the device.</p>
        </fieldset>
      ) : (
        <p className="muted">
          Devices you enrol as a member start without tags. An admin can add them later.
        </p>
      )}
      <div className="ui-form-actions">
        <Button type="submit" loading={pending} loadingLabel="Approving…">
          Approve this device
        </Button>
      </div>
    </form>
  );
}
