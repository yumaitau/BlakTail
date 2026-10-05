"use client";

import { useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { createInvitationAction, revokeInvitationAction } from "@/app/actions";
import { formatDateTime } from "@/lib/format-time";
import { ORG_ROLES, roleImpact, roleLabel, type OrgRole } from "@/lib/roles";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { SecretPanel } from "./ui/secret-panel";
import { Section } from "./ui/section";
import { EmptyRow, Table, Td } from "./ui/table";
import { toast, toastResult } from "./ui/toast";

const INVITABLE_ROLES = ORG_ROLES.filter((role) => role !== "owner");

type PendingInvitation = {
  id: string;
  email: string;
  role: Exclude<OrgRole, "owner">;
  expiresAt: string;
};

export function InvitationManager({ invitations }: { invitations: PendingInvitation[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [invitationUrl, setInvitationUrl] = useState<string | null>(null);
  const [role, setRole] = useState<Exclude<OrgRole, "owner">>("member");
  const [emailError, setEmailError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<PendingInvitation | null>(null);
  const formRef = useRef<HTMLFormElement>(null);

  return (
    <Section
      id="invitations"
      headingLevel={3}
      title="Invitations"
      description="Invite someone by email. New people create an account; people who already have one add this organisation to their sign-in. Each link works once."
    >
      <form
        ref={formRef}
        className="form-row"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          const form = new FormData(formElement);
          const email = String(form.get("email") ?? "").trim();
          if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(email)) {
            setEmailError("Enter the person's email address, like name@example.org.au.");
            formElement.querySelector<HTMLInputElement>("[name='email']")?.focus();
            return;
          }
          setEmailError(null);
          setInvitationUrl(null);
          startTransition(async () => {
            const result = await createInvitationAction(form);
            if (!result.ok) {
              const fields = toastResult(result, { errorToast: false });
              if (fields.email) setEmailError(fields.email);
              return;
            }
            formElement.reset();
            setRole("member");
            setInvitationUrl(result.data.url);
            toast.success("Invitation created", { description: `For ${email}.` });
            router.refresh();
          });
        }}
      >
        <FormField label="Email" required error={emailError}>
          <input name="email" type="email" autoComplete="off" />
        </FormField>
        <FormField label="Role" className="field-narrow">
          <select
            name="role"
            value={role}
            aria-describedby="invitation-role-impact"
            onChange={(event) => setRole(event.currentTarget.value as Exclude<OrgRole, "owner">)}
          >
            {INVITABLE_ROLES.map((option) => (
              <option key={option} value={option}>
                {roleLabel(option)}
              </option>
            ))}
          </select>
        </FormField>
        <Button type="submit" loading={pending} loadingLabel="Creating…">
          Create invitation
        </Button>
      </form>
      <p className="muted form-note" id="invitation-role-impact">
        {roleLabel(role)}: {roleImpact(role)}
      </p>
      {invitationUrl ? (
        <SecretPanel
          title="Copy the invitation link now"
          label="Invitation link"
          secret={invitationUrl}
          description="Anyone with this link can join as the invited person, so send it through a channel you trust. It's shown only once and works once."
          onDone={() => setInvitationUrl(null)}
        />
      ) : null}
      <Table label="Pending invitations" mobile="stack">
        <thead>
          <tr>
            <th scope="col">Email</th>
            <th scope="col">Role</th>
            <th scope="col">Expires</th>
            <th scope="col">
              <span className="visually-hidden">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {invitations.length === 0 ? (
            <EmptyRow colSpan={4}>No pending invitations.</EmptyRow>
          ) : (
            invitations.map((invitation) => (
              <tr key={invitation.id}>
                <Td label="Email">
                  <span className="cell-break">{invitation.email}</span>
                </Td>
                <Td label="Role">{roleLabel(invitation.role)}</Td>
                <Td label="Expires">{formatDateTime(invitation.expiresAt)}</Td>
                <Td>
                  <div className="cell-actions">
                    <Button
                      size="sm"
                      variant="quiet-danger"
                      disabled={pending}
                      onClick={() => setRevoking(invitation)}
                    >
                      Revoke
                    </Button>
                  </div>
                </Td>
              </tr>
            ))
          )}
        </tbody>
      </Table>
      <ConfirmDialog
        open={revoking !== null}
        title="Revoke this invitation?"
        description={
          revoking ? `The link sent to ${revoking.email} stops working. You can invite them again later.` : null
        }
        confirmLabel="Revoke invitation"
        pending={pending}
        onCancel={() => setRevoking(null)}
        onConfirm={() => {
          if (!revoking) return;
          const form = new FormData();
          form.set("invitationId", revoking.id);
          const email = revoking.email;
          startTransition(async () => {
            const result = await revokeInvitationAction(form);
            setRevoking(null);
            toastResult(result, { success: "Invitation revoked", successDescription: email });
            if (result.ok) router.refresh();
          });
        }}
      />
    </Section>
  );
}
