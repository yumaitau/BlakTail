"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { changeMembershipAction } from "@/app/actions";
import {
  ORG_ROLES,
  ownerChangeRefusal,
  permissionReason,
  roleImpact,
  roleLabel,
  type OrgRole,
} from "@/lib/roles";
import { Alert } from "./ui/alert";
import { StatusPill, type BadgeTone } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { Section } from "./ui/section";
import { EmptyRow, Table, Td } from "./ui/table";
import { toast, toastResult } from "./ui/toast";

export type MembershipSummary = {
  id: string;
  userId: string;
  role: OrgRole;
  status: "invited" | "active" | "suspended" | "removed";
  email: string;
  name: string;
  hasPassword: boolean;
};

type Change = { membershipId: string; role?: OrgRole; status?: "active" | "suspended" | "removed" };

const STATUS: Record<MembershipSummary["status"], { label: string; tone: BadgeTone }> = {
  active: { label: "Active", tone: "success" },
  invited: { label: "Invited", tone: "warning" },
  suspended: { label: "Suspended", tone: "danger" },
  removed: { label: "Removed", tone: "muted" },
};

export function MembershipManager({
  memberships,
  actorRole,
  organisationName,
}: {
  memberships: MembershipSummary[];
  actorRole: OrgRole;
  organisationName: string;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busyId, setBusyId] = useState<string | null>(null);
  const [draftRoles, setDraftRoles] = useState<Record<string, OrgRole>>({});
  const [confirm, setConfirm] = useState<{ row: MembershipSummary; status: "suspended" | "removed" } | null>(
    null,
  );
  const denied = permissionReason(actorRole, "manage_security");
  const seats = memberships.map((row) => ({
    membershipId: row.id,
    role: row.role,
    status: row.status,
    hasPassword: row.hasPassword,
  }));
  const blockedBy = (change: Change) => denied ?? ownerChangeRefusal(seats, change);

  function apply(change: Change, done: string, after?: () => void) {
    const form = new FormData();
    form.set("membershipId", change.membershipId);
    if (change.role) form.set("role", change.role);
    if (change.status) form.set("status", change.status);
    setBusyId(change.membershipId);
    startTransition(async () => {
      const result = await changeMembershipAction(form);
      setBusyId(null);
      after?.();
      if (!result.ok) {
        toastResult(result);
        return;
      }
      toast.success(done);
      if (change.role) {
        setDraftRoles((current) => {
          const next = { ...current };
          delete next[change.membershipId];
          return next;
        });
      }
      router.refresh();
    });
  }

  return (
    <Section
      id="members"
      headingLevel={3}
      title="Members and roles"
      description={`Roles apply to ${organisationName} only. Suspended or removed people lose console access straight away; their devices stay. There is always an active owner, and an active password owner if there is one.`}
    >
      {denied ? <Alert tone="info">{denied}</Alert> : null}
      <Table label={`Members of ${organisationName}`} mobile="stack">
        <thead>
          <tr>
            <th scope="col">Person</th>
            <th scope="col">Role</th>
            <th scope="col">Status</th>
            <th scope="col">
              <span className="visually-hidden">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {memberships.length === 0 ? (
            <EmptyRow colSpan={4}>No one is a member yet. Invite someone below.</EmptyRow>
          ) : (
            memberships.map((row) => {
              const draft = draftRoles[row.id] ?? row.role;
              const roleChange: Change = { membershipId: row.id, role: draft };
              const roleBlocked = draft === row.role ? null : blockedBy(roleChange);
              const nextStatus = row.status === "active" ? "suspended" : "active";
              const statusBlocked = blockedBy({ membershipId: row.id, status: nextStatus });
              const removeBlocked = blockedBy({ membershipId: row.id, status: "removed" });
              const selectId = `role-${row.id}`;
              const impactId = `role-impact-${row.id}`;
              const busy = pending && busyId === row.id;
              return (
                <tr key={row.id}>
                  <Td label="Person">
                    <span>{row.name}</span>
                    <span className="cell-sub">{row.email}</span>
                    {row.role === "owner" && row.hasPassword ? (
                      <span className="cell-sub">Password sign-in (break-glass)</span>
                    ) : null}
                  </Td>
                  <Td label="Role">
                    <div className="stack tight member-role">
                      <label htmlFor={selectId} className="visually-hidden">
                        Role for {row.name}
                      </label>
                      <select
                        id={selectId}
                        value={draft}
                        disabled={pending || Boolean(denied) || row.status === "removed"}
                        aria-describedby={impactId}
                        onChange={(event) =>
                          setDraftRoles((current) => ({
                            ...current,
                            [row.id]: event.currentTarget.value as OrgRole,
                          }))
                        }
                      >
                        {ORG_ROLES.map((role) => (
                          <option key={role} value={role}>
                            {roleLabel(role)}
                          </option>
                        ))}
                      </select>
                      <span className="cell-sub" id={impactId}>
                        {roleImpact(draft)}
                      </span>
                      {draft !== row.role ? (
                        <div className="actions">
                          <Button
                            size="sm"
                            loading={busy}
                            loadingLabel="Saving…"
                            disabled={pending || Boolean(roleBlocked)}
                            title={roleBlocked ?? undefined}
                            onClick={() =>
                              apply(roleChange, `${row.name} is now ${roleLabel(draft).toLowerCase()}`)
                            }
                          >
                            Save role
                          </Button>
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={pending}
                            onClick={() =>
                              setDraftRoles((current) => {
                                const next = { ...current };
                                delete next[row.id];
                                return next;
                              })
                            }
                          >
                            Undo
                          </Button>
                        </div>
                      ) : null}
                      {roleBlocked ? <span className="cell-sub">{roleBlocked}</span> : null}
                    </div>
                  </Td>
                  <Td label="Status">
                    <StatusPill tone={STATUS[row.status].tone}>{STATUS[row.status].label}</StatusPill>
                  </Td>
                  <Td>
                    <div className="cell-actions">
                      {row.status === "removed" ? null : row.status === "active" ? (
                        <Button
                          size="sm"
                          variant="secondary"
                          disabled={pending || Boolean(statusBlocked)}
                          title={statusBlocked ?? undefined}
                          onClick={() => setConfirm({ row, status: "suspended" })}
                        >
                          Suspend
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          variant="secondary"
                          loading={busy}
                          disabled={pending || Boolean(statusBlocked)}
                          title={statusBlocked ?? undefined}
                          onClick={() =>
                            apply({ membershipId: row.id, status: "active" }, `${row.name} is active again`)
                          }
                        >
                          Restore
                        </Button>
                      )}
                      {row.status === "removed" ? null : (
                        <Button
                          size="sm"
                          variant="quiet-danger"
                          disabled={pending || Boolean(removeBlocked)}
                          title={removeBlocked ?? undefined}
                          onClick={() => setConfirm({ row, status: "removed" })}
                        >
                          Remove
                        </Button>
                      )}
                    </div>
                    {statusBlocked && !denied && row.role === "owner" ? (
                      <span className="cell-sub">{statusBlocked}</span>
                    ) : null}
                  </Td>
                </tr>
              );
            })
          )}
        </tbody>
      </Table>
      <ConfirmDialog
        open={confirm !== null}
        title={confirm?.status === "removed" ? "Remove this member?" : "Suspend this member?"}
        description={
          confirm
            ? confirm.status === "removed"
              ? `${confirm.row.name} (${confirm.row.email}) loses access to ${organisationName} straight away and their remote sessions end. Their devices and audit history stay. To bring them back you'd send a new invitation.`
              : `${confirm.row.name} loses console access straight away and their remote sessions end. You can restore them later.`
            : null
        }
        confirmText={confirm?.status === "removed" ? confirm.row.email : undefined}
        confirmLabel={confirm?.status === "removed" ? "Remove member" : "Suspend"}
        pending={pending}
        onCancel={() => setConfirm(null)}
        onConfirm={() => {
          if (!confirm) return;
          const { row, status } = confirm;
          apply(
            { membershipId: row.id, status },
            status === "removed" ? `${row.name} was removed` : `${row.name} is suspended`,
            () => setConfirm(null),
          );
        }}
      />
    </Section>
  );
}
