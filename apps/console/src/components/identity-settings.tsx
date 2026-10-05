"use client";

import { useRouter } from "next/navigation";
import { useRef, useState, useTransition } from "react";
import {
  beginIdentityLinkAction,
  completeIdentityLinkAction,
  recoverIdentityAction,
  resolveIdentityRoleConflictAction,
  suspendIdentityAction,
  unlinkIdentityAction,
} from "@/app/identity-actions";
import type {
  LoginIdentitySummary,
  NetworkAccountSummary,
  PendingRoleConflict,
} from "@/lib/identity-links";
import { LocalTime } from "./ui/local-time";
import { roleLabel } from "@/lib/roles";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { Section } from "./ui/section";
import { StatusPill } from "./ui/badge";
import { EmptyRow, Table, Td } from "./ui/table";
import { toast, toastResult } from "./ui/toast";

const METHOD_LABEL: Record<string, string> = {
  credential: "Password",
  oidc: "Single sign-on",
};

type Operation = "unlink" | "revoke" | "recover";

const OPERATION_COPY: Record<
  Operation,
  { title: string; confirm: string; tone: "danger" | "primary"; done: string; body: (email: string) => string }
> = {
  unlink: {
    title: "Unlink this sign-in",
    confirm: "Unlink",
    tone: "danger",
    done: "Sign-in unlinked",
    body: (email) =>
      `${email} stops being a way into this account, and its organisations leave this session. The sign-in itself still exists and can be linked again.`,
  },
  revoke: {
    title: "Revoke this sign-in",
    confirm: "Revoke",
    tone: "danger",
    done: "Sign-in revoked",
    body: (email) =>
      `${email} can no longer sign in, and its memberships stop giving access. You can recover it later from here.`,
  },
  recover: {
    title: "Recover this sign-in",
    confirm: "Recover",
    tone: "primary",
    done: "Sign-in recovered",
    body: (email) => `${email} can sign in again and its memberships give access again.`,
  },
};

export function IdentitySettings({
  identities,
  networkAccounts,
  conflicts,
}: {
  identities: LoginIdentitySummary[];
  networkAccounts: NetworkAccountSummary[];
  conflicts: PendingRoleConflict[];
}) {
  const router = useRouter();
  const [challenge, setChallenge] = useState<{ token: string; expiresAt: string } | null>(null);
  const [pending, startTransition] = useTransition();
  const [confirm, setConfirm] = useState<{ identity: LoginIdentitySummary; operation: Operation } | null>(
    null,
  );
  const [confirmPassword, setConfirmPassword] = useState("");
  const [confirmError, setConfirmError] = useState<string | null>(null);
  const [linkErrors, setLinkErrors] = useState<Record<string, string>>({});
  const [conflictError, setConflictError] = useState<Record<string, string>>({});
  const linkForm = useRef<HTMLFormElement>(null);
  const onlyOne = identities.length <= 1;

  function closeConfirm() {
    setConfirm(null);
    setConfirmPassword("");
    setConfirmError(null);
  }

  return (
    <>
      <Section
        id="identities"
        headingLevel={3}
        title="Ways to sign in"
        description="Each sign-in authenticates on its own. Passwords, provider tokens and two-step settings are never copied between linked sign-ins."
      >
        <Table label="Sign-in identities" mobile="stack">
          <thead>
            <tr>
              <th scope="col">Sign-in</th>
              <th scope="col">Method</th>
              <th scope="col">Status</th>
              <th scope="col">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {identities.map((identity) => (
              <tr key={identity.userId}>
                <Td label="Sign-in">
                  <span className="cell-break">{identity.email}</span>
                  <span className="cell-sub">{identity.name}</span>
                </Td>
                <Td label="Method">
                  {identity.methods.map((method) => METHOD_LABEL[method] ?? (method.startsWith("oidc") ? "Single sign-on" : method)).join(", ") ||
                    "Identity provider"}
                </Td>
                <Td label="Status">
                  {identity.current ? (
                    <StatusPill tone="success">This session</StatusPill>
                  ) : identity.status === "suspended" ? (
                    <StatusPill tone="danger">Revoked</StatusPill>
                  ) : (
                    <StatusPill tone="neutral">Linked</StatusPill>
                  )}
                </Td>
                <Td>
                  {identity.current ? null : (
                    <div className="cell-actions">
                      {identity.status === "suspended" ? (
                        <Button
                          size="sm"
                          variant="secondary"
                          disabled={pending}
                          onClick={() => setConfirm({ identity, operation: "recover" })}
                        >
                          Recover
                        </Button>
                      ) : (
                        <>
                          <Button
                            size="sm"
                            variant="secondary"
                            disabled={pending || onlyOne}
                            title={onlyOne ? "Your only sign-in can't be unlinked." : undefined}
                            onClick={() => setConfirm({ identity, operation: "unlink" })}
                          >
                            Unlink
                          </Button>
                          <Button
                            size="sm"
                            variant="quiet-danger"
                            disabled={pending || onlyOne}
                            title={onlyOne ? "Your only sign-in can't be revoked." : undefined}
                            onClick={() => setConfirm({ identity, operation: "revoke" })}
                          >
                            Revoke
                          </Button>
                        </>
                      )}
                    </div>
                  )}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>

        {challenge ? (
          <form
            ref={linkForm}
            className="ui-subsection"
            noValidate
            aria-labelledby="link-login-title"
            onSubmit={(event) => {
              event.preventDefault();
              const formData = new FormData(event.currentTarget);
              const errors: Record<string, string> = {};
              if (!String(formData.get("currentPassword") ?? "")) errors.currentPassword = "Enter your current password.";
              if (!String(formData.get("email") ?? "").includes("@")) errors.email = "Enter the other sign-in's email address.";
              if (!String(formData.get("password") ?? "")) errors.password = "Enter the other sign-in's password.";
              setLinkErrors(errors);
              if (Object.keys(errors).length) return;
              startTransition(async () => {
                const result = await completeIdentityLinkAction(formData);
                if (!result.ok) {
                  setChallenge(null);
                  toastResult(result);
                  return;
                }
                setChallenge(null);
                toast.success(
                  result.data.ownerResolutionRequired ? "Sign-in checked, owner decision needed" : "Sign-in linked",
                  {
                    description: result.data.ownerResolutionRequired
                      ? "The roles differ, so an owner must choose the effective role before linking finishes."
                      : "Its organisations are now available in this session.",
                  },
                );
                router.refresh();
              });
            }}
          >
            <div className="ui-subsection-head">
              <h4 id="link-login-title" className="card-heading">
                Link another sign-in
              </h4>
              <p className="muted">
                Sign in again with both. An email address or an open browser session isn&apos;t
                enough. This request expires <LocalTime value={challenge.expiresAt} />.
              </p>
            </div>
            <input type="hidden" name="challenge" value={challenge.token} />
            <div className="form-grid">
              <FormField label="Your current password" required error={linkErrors.currentPassword}>
                <input name="currentPassword" type="password" autoComplete="current-password" disabled={pending} />
              </FormField>
              <FormField label="Other sign-in email" required error={linkErrors.email}>
                <input name="email" type="email" autoComplete="username" disabled={pending} />
              </FormField>
              <FormField label="Other sign-in password" required error={linkErrors.password}>
                <input name="password" type="password" autoComplete="off" disabled={pending} />
              </FormField>
            </div>
            <div className="actions">
              <Button type="submit" loading={pending} loadingLabel="Linking…">
                Check both and link
              </Button>
              <Button variant="secondary" disabled={pending} onClick={() => setChallenge(null)}>
                Cancel
              </Button>
            </div>
          </form>
        ) : (
          <div className="actions">
            <Button
              variant="secondary"
              loading={pending}
              loadingLabel="Starting…"
              onClick={() => {
                startTransition(async () => {
                  const result = await beginIdentityLinkAction();
                  if (!result.ok) {
                    toastResult(result);
                    return;
                  }
                  setLinkErrors({});
                  setChallenge(result.data);
                });
              }}
            >
              Link another sign-in
            </Button>
          </div>
        )}

        <div className="ui-subsection">
          <div className="ui-subsection-head">
            <h4 className="card-heading">Network accounts</h4>
            <p className="muted">
              Organisation memberships that add devices to All networks. Roles and network state
              stay separate for each organisation.
            </p>
          </div>
          <Table label="Network accounts" mobile="stack">
            <thead>
              <tr>
                <th scope="col">Network account</th>
                <th scope="col">Organisation</th>
                <th scope="col">Role</th>
              </tr>
            </thead>
            <tbody>
              {networkAccounts.length === 0 ? (
                <EmptyRow colSpan={3}>
                  No active network accounts. Accept an invitation, or ask an owner to add you to an
                  organisation.
                </EmptyRow>
              ) : (
                networkAccounts.map((account) => (
                  <tr key={account.id}>
                    <Td label="Account">{account.name}</Td>
                    <Td label="Organisation">{account.organisationName}</Td>
                    <Td label="Role">{roleLabel(account.role)}</Td>
                  </tr>
                ))
              )}
            </tbody>
          </Table>
        </div>
      </Section>

      {conflicts.length > 0 ? (
        <Section
          id="role-conflicts"
          headingLevel={3}
          title="Owner role decisions"
          description="Two linked sign-ins hold different roles. Both memberships stay as they are; choose the role that applies when they act as one person. The decision is audited."
        >
          {conflicts.map((conflict) => (
            <form
              key={conflict.id}
              className="form-row"
              noValidate
              onSubmit={(event) => {
                event.preventDefault();
                const formData = new FormData(event.currentTarget);
                if (!formData.get("resolvedRole")) {
                  setConflictError({ [conflict.id]: "Choose the role that applies." });
                  return;
                }
                setConflictError({});
                startTransition(async () => {
                  const result = await resolveIdentityRoleConflictAction(formData);
                  if (!result.ok) {
                    toastResult(result);
                    return;
                  }
                  toast.success(result.data.linked ? "Role chosen and sign-in linked" : "Role decision recorded", {
                    description: result.data.linked ? undefined : "Another owner decision is still needed.",
                  });
                  router.refresh();
                });
              }}
            >
              <input type="hidden" name="conflictId" value={conflict.id} />
              <FormField label={`Effective role in ${conflict.organisationName}`} error={conflictError[conflict.id]}>
                <select name="resolvedRole" defaultValue="">
                  <option value="" disabled>
                    Choose a role
                  </option>
                  {[conflict.requesterRole, conflict.targetRole].map((role) => (
                    <option value={role} key={role}>
                      {roleLabel(role)}
                    </option>
                  ))}
                </select>
              </FormField>
              <Button type="submit" loading={pending} loadingLabel="Saving…">
                Record decision
              </Button>
            </form>
          ))}
        </Section>
      ) : null}

      <ConfirmDialog
        open={confirm !== null}
        title={confirm ? OPERATION_COPY[confirm.operation].title : ""}
        description={confirm ? OPERATION_COPY[confirm.operation].body(confirm.identity.email) : null}
        confirmLabel={confirm ? OPERATION_COPY[confirm.operation].confirm : "Confirm"}
        tone={confirm ? OPERATION_COPY[confirm.operation].tone : "danger"}
        pending={pending}
        onCancel={closeConfirm}
        onConfirm={() => {
          if (!confirm) return;
          if (!confirmPassword) {
            setConfirmError("Enter your current password to confirm.");
            return;
          }
          const { identity, operation } = confirm;
          const formData = new FormData();
          formData.set("identityUserId", identity.userId);
          formData.set("currentPassword", confirmPassword);
          startTransition(async () => {
            const result =
              operation === "unlink"
                ? await unlinkIdentityAction(formData)
                : operation === "recover"
                  ? await recoverIdentityAction(formData)
                  : await suspendIdentityAction(formData);
            if (!result.ok) {
              setConfirmError(result.error);
              return;
            }
            closeConfirm();
            toast.success(OPERATION_COPY[operation].done, { description: identity.email });
            router.refresh();
          });
        }}
      >
        <FormField label="Your current password" required error={confirmError}>
          <input
            type="password"
            autoComplete="current-password"
            value={confirmPassword}
            onChange={(event) => setConfirmPassword(event.currentTarget.value)}
          />
        </FormField>
      </ConfirmDialog>
    </>
  );
}
