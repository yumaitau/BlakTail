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
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [draftRoles, setDraftRoles] = useState<Record<string, OrgRole>>({});
  const denied = permissionReason(actorRole, "manage_security");
  const seats = memberships.map((row) => ({
    membershipId: row.id,
    role: row.role,
    status: row.status,
    hasPassword: row.hasPassword,
  }));
  const blockedBy = (change: Change) => denied ?? ownerChangeRefusal(seats, change);

  function apply(change: Change, done: string) {
    const form = new FormData();
    form.set("membershipId", change.membershipId);
    if (change.role) form.set("role", change.role);
    if (change.status) form.set("status", change.status);
    setError(null);
    setNotice(null);
    startTransition(async () => {
      const result = await changeMembershipAction(form);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setNotice(done);
      router.refresh();
    });
  }

  return (
    <div className="panel stack">
      <div>
        <h2>Membership</h2>
        <p className="muted">
          Changing <strong>{organisationName}</strong> as{" "}
          {roleLabel(actorRole).toLowerCase()}. Roles apply to this organisation
          only; a person&apos;s role elsewhere never carries over. Every change is
          audited. Suspended or removed people lose console access
          immediately; their device records stay intact. The organisation
          always keeps an active owner, and an active password owner if it
          has one.
        </p>
      </div>
      {denied ? <p className="muted">{denied}</p> : null}
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p className="muted" role="status">
          {notice}
        </p>
      ) : null}
      {memberships.length === 0 ? (
        <p className="muted">No people are members of this organisation yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Person</th>
                <th>Role</th>
                <th>Status</th>
                <th>Access</th>
              </tr>
            </thead>
            <tbody>
              {memberships.map((row) => {
                const draft = draftRoles[row.id] ?? row.role;
                const roleChange: Change = { membershipId: row.id, role: draft };
                const roleBlocked = draft === row.role ? null : blockedBy(roleChange);
                const nextStatus = row.status === "active" ? "suspended" : "active";
                const statusBlocked = blockedBy({ membershipId: row.id, status: nextStatus });
                const removeBlocked = blockedBy({ membershipId: row.id, status: "removed" });
                const selectId = `role-${row.id}`;
                const impactId = `role-impact-${row.id}`;
                return (
                  <tr key={row.id}>
                    <td>
                      <div>{row.name}</div>
                      <div className="muted mono">{row.email}</div>
                      {row.role === "owner" && row.hasPassword ? (
                        <div className="muted">Password sign-in (break-glass)</div>
                      ) : null}
                    </td>
                    <td>
                      <div className="stack">
                        <label htmlFor={selectId}>
                          <span className="visually-hidden">Role for {row.name}</span>
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
                        </label>
                        <p className="muted" id={impactId}>
                          {roleImpact(draft)}
                        </p>
                        {draft !== row.role ? (
                          <>
                            <button
                              type="button"
                              disabled={pending || Boolean(roleBlocked)}
                              title={roleBlocked ?? undefined}
                              onClick={() =>
                                apply(
                                  roleChange,
                                  `${row.name} is now ${roleLabel(draft).toLowerCase()} in ${organisationName}.`,
                                )
                              }
                            >
                              Change {roleLabel(row.role).toLowerCase()} to{" "}
                              {roleLabel(draft).toLowerCase()}
                            </button>
                            {roleBlocked ? <p className="muted">{roleBlocked}</p> : null}
                          </>
                        ) : null}
                      </div>
                    </td>
                    <td>
                      <span
                        className={
                          row.status === "active"
                            ? "badge online"
                            : row.status === "invited"
                              ? "badge pending"
                              : "badge revoked"
                        }
                      >
                        {row.status}
                      </span>
                    </td>
                    <td>
                      <div className="stack">
                        <button
                          type="button"
                          className="secondary"
                          disabled={pending || Boolean(statusBlocked)}
                          title={statusBlocked ?? undefined}
                          onClick={() =>
                            apply(
                              { membershipId: row.id, status: nextStatus },
                              `${row.name} is now ${nextStatus}.`,
                            )
                          }
                        >
                          {row.status === "active" ? "Suspend" : "Restore"}
                        </button>
                        {row.status === "removed" ? null : (
                          <button
                            type="button"
                            className="danger"
                            disabled={pending || Boolean(removeBlocked)}
                            title={removeBlocked ?? undefined}
                            onClick={() =>
                              apply(
                                { membershipId: row.id, status: "removed" },
                                `${row.name} was removed.`,
                              )
                            }
                          >
                            Remove
                          </button>
                        )}
                        {statusBlocked && !denied && row.role === "owner" ? (
                          <p className="muted">{statusBlocked}</p>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
