"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  addDomainAction,
  removeDomainAction,
  saveSignInPolicyAction,
  verifyDomainAction,
} from "@/app/settings/actions";
import type { SignInPolicy } from "@/lib/auth-policy-core";
import type { OrganisationDomain } from "@/lib/auth-policy";
import { LocalTime } from "./ui/local-time";
import { Alert } from "./ui/alert";
import { StatusPill } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { Section } from "./ui/section";
import { EmptyRow, Table, Td } from "./ui/table";
import { toast, toastResult } from "./ui/toast";

const DOMAIN = /^(?=.{1,253}$)(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$/iu;

export function SignInSecurity({
  organisationName,
  policy,
  domains,
  denied,
}: {
  organisationName: string;
  policy: SignInPolicy;
  domains: OrganisationDomain[];
  /** Why the viewer cannot change these settings, or null. */
  denied: string | null;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<string | null>(null);
  const [errors, setErrors] = useState<{ stepUp?: string; domain?: string }>({});
  const [removing, setRemoving] = useState<OrganisationDomain | null>(null);
  const locked = pending || Boolean(denied);

  return (
    <Section
      id="sign-in-policy"
      headingLevel={3}
      title="Sign-in policy"
      description={`Applies to ${organisationName} only. Someone in several organisations meets each organisation's rules separately. Changes are audited.`}
    >
      {denied ? <Alert tone="info">{denied}</Alert> : null}
      <form
        className="ui-form"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          const minutes = String(form.get("stepUpMaxAgeMinutes") ?? "").trim();
          if (minutes && (!/^\d+$/u.test(minutes) || Number(minutes) < 5 || Number(minutes) > 1440)) {
            setErrors({ stepUp: "Use a whole number of minutes from 5 to 1440, or leave it empty." });
            return;
          }
          setErrors({});
          if (!form.get("requireMfaForPrivileged")) form.set("requireMfaForPrivileged", "false");
          setBusy("policy");
          startTransition(async () => {
            const result = await saveSignInPolicyAction(form);
            setBusy(null);
            toastResult(result, { success: "Sign-in policy saved" });
            if (result.ok) router.refresh();
          });
        }}
      >
        <FormField
          label="Ask for a fresh sign-in before security changes (minutes)"
          hint="Leave empty for no requirement. When set, changes to people, roles, single sign-on, directory sync, sign-in domains, this policy and API clients need a sign-in at most this old."
          error={errors.stepUp}
          className="field-narrow"
        >
          <input
            name="stepUpMaxAgeMinutes"
            type="number"
            inputMode="numeric"
            min={5}
            max={1440}
            step={1}
            defaultValue={policy.stepUpMaxAgeMinutes ?? ""}
            disabled={locked}
          />
        </FormField>
        <label className="check-option">
          <input
            type="checkbox"
            name="requireMfaForPrivileged"
            value="true"
            defaultChecked={policy.requireMfaForPrivileged}
            disabled={locked}
          />
          <span>
            Require two-step verification for owners and admins who sign in with a password
            <span className="muted">
              Without it they can still sign in and turn it on, but can&apos;t make changes. Single
              sign-on relies on the identity provider&apos;s own multi-factor rules.
            </span>
          </span>
        </label>
        <div className="actions">
          <Button
            type="submit"
            loading={busy === "policy"}
            loadingLabel="Saving…"
            disabled={locked}
            title={denied ?? undefined}
          >
            Save sign-in policy
          </Button>
        </div>
      </form>

      <div className="ui-subsection" id="domains">
        <div className="ui-subsection-head">
          <h4 className="card-heading">Verified sign-in domains</h4>
          <p className="muted">
            Prove you own a domain with a DNS TXT record. Once any domain is verified, single
            sign-on only adds people automatically if their email is in a verified domain. A
            domain verified by another organisation can&apos;t be claimed here.
          </p>
        </div>
        <form
          className="form-row"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            const formElement = event.currentTarget;
            const form = new FormData(formElement);
            const domain = String(form.get("domain") ?? "").trim().toLowerCase();
            if (!DOMAIN.test(domain)) {
              setErrors({ domain: "Enter a domain name like example.org.au, without https:// or a path." });
              formElement.querySelector<HTMLInputElement>("[name='domain']")?.focus();
              return;
            }
            setErrors({});
            setBusy("add");
            startTransition(async () => {
              const result = await addDomainAction(form);
              setBusy(null);
              if (!result.ok) {
                // Validation comes back without a reference: show it on the field.
                if (result.ref) toastResult(result);
                else setErrors({ domain: result.error });
                return;
              }
              formElement.reset();
              toast.success("Domain added", {
                description: "Publish the TXT record shown below, then check it.",
              });
              router.refresh();
            });
          }}
        >
          <FormField label="Domain" error={errors.domain}>
            <input name="domain" placeholder="example.org.au" autoComplete="off" disabled={locked} />
          </FormField>
          <Button type="submit" variant="secondary" loading={busy === "add"} loadingLabel="Adding…" disabled={locked}>
            Add domain
          </Button>
        </form>
        <Table label="Sign-in domains" mobile="stack">
          <thead>
            <tr>
              <th scope="col">Domain</th>
              <th scope="col">TXT record</th>
              <th scope="col">Status</th>
              <th scope="col">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {domains.length === 0 ? (
              <EmptyRow colSpan={4}>No sign-in domains yet.</EmptyRow>
            ) : (
              domains.map((domain) => (
                <tr key={domain.id}>
                  <Td label="Domain" className="cell-nowrap">
                    {domain.domain}
                  </Td>
                  <Td label="TXT record">
                    <span className="mono cell-break">{domain.txtName}</span>
                    <span className="cell-sub mono cell-break">{domain.txtValue}</span>
                  </Td>
                  <Td label="Status">
                    <StatusPill tone={domain.verifiedAt ? "success" : "warning"}>
                      {domain.verifiedAt ? "Verified" : "Not verified"}
                    </StatusPill>
                    {domain.lastCheckedAt ? (
                      <span className="cell-sub">Checked <LocalTime value={domain.lastCheckedAt} /></span>
                    ) : null}
                  </Td>
                  <Td>
                    <div className="cell-actions">
                      {domain.verifiedAt ? null : (
                        <Button
                          size="sm"
                          variant="secondary"
                          loading={busy === domain.id}
                          loadingLabel="Checking…"
                          disabled={locked}
                          onClick={() => {
                            const form = new FormData();
                            form.set("domainId", domain.id);
                            setBusy(domain.id);
                            startTransition(async () => {
                              const result = await verifyDomainAction(form);
                              setBusy(null);
                              if (!result.ok) {
                                toastResult(result);
                                return;
                              }
                              if (result.data.verified) {
                                toast.success(`${domain.domain} is verified`);
                              } else {
                                toast.warning(`No matching TXT record for ${domain.domain} yet`, {
                                  description: "DNS changes can take a while to appear. Check again later.",
                                });
                              }
                              router.refresh();
                            });
                          }}
                        >
                          Check TXT record
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="quiet-danger"
                        disabled={locked}
                        onClick={() => setRemoving(domain)}
                      >
                        Remove
                      </Button>
                    </div>
                  </Td>
                </tr>
              ))
            )}
          </tbody>
        </Table>
      </div>
      <ConfirmDialog
        open={removing !== null}
        title="Remove this sign-in domain?"
        description={
          removing
            ? removing.verifiedAt
              ? `${removing.domain} stops limiting who single sign-on can add. If it's your only verified domain, any allowed email can join again.`
              : `${removing.domain} and its TXT record details are removed.`
            : null
        }
        confirmLabel="Remove domain"
        pending={pending}
        onCancel={() => setRemoving(null)}
        onConfirm={() => {
          if (!removing) return;
          const form = new FormData();
          form.set("domainId", removing.id);
          const name = removing.domain;
          startTransition(async () => {
            const result = await removeDomainAction(form);
            setRemoving(null);
            toastResult(result, { success: `${name} removed` });
            if (result.ok) router.refresh();
          });
        }}
      />
    </Section>
  );
}
