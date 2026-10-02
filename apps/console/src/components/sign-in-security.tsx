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
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const locked = pending || Boolean(denied);

  function submit(
    action: (form: FormData) => Promise<{ ok: true; data: unknown } | { ok: false; error: string }>,
    form: FormData,
    done: string | ((data: unknown) => string),
  ) {
    setError(null);
    setNotice(null);
    startTransition(async () => {
      const result = await action(form);
      if (!result.ok) {
        setError(result.error);
        return;
      }
      setNotice(typeof done === "string" ? done : done(result.data));
      router.refresh();
    });
  }

  return (
    <div className="panel stack">
      <div>
        <h2>Sign-in policy</h2>
        <p className="muted">
          Applies to <strong>{organisationName}</strong> only. A person linked to
          several organisations meets each organisation&apos;s rule separately.
          Changes are audited.
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
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          if (!form.get("requireMfaForPrivileged")) form.set("requireMfaForPrivileged", "false");
          submit(saveSignInPolicyAction, form, "Sign-in policy saved.");
        }}
      >
        <label>
          Re-authenticate for security changes after (minutes)
          <input
            name="stepUpMaxAgeMinutes"
            type="number"
            min={5}
            max={1440}
            step={1}
            defaultValue={policy.stepUpMaxAgeMinutes ?? ""}
            disabled={locked}
            aria-describedby="step-up-help"
          />
        </label>
        <p className="muted" id="step-up-help">
          Leave empty for no requirement. When set, changes to people, roles,
          single sign-on, directory sync, sign-in domains, this policy and
          automation credentials need a sign-in at most this old.
        </p>
        <label className="route-option">
          <input
            type="checkbox"
            name="requireMfaForPrivileged"
            value="true"
            defaultChecked={policy.requireMfaForPrivileged}
            disabled={locked}
          />
          Require two-step verification for owners and admins who sign in with
          a password
        </label>
        <p className="muted">
          Owners and admins without it can still sign in and turn it on; they
          cannot make changes until they do. Single sign-on identities rely on
          the identity provider&apos;s own multi-factor policy.
        </p>
        <button type="submit" disabled={locked} title={denied ?? undefined}>
          Save sign-in policy
        </button>
      </form>

      <div>
        <h3>Verified sign-in domains</h3>
        <p className="muted">
          Prove a domain with a DNS TXT record. Once any domain is verified,
          just-in-time single sign-on membership accepts only email addresses
          in verified domains. A domain verified by another organisation
          cannot be claimed here.
        </p>
      </div>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const formElement = event.currentTarget;
          submit(addDomainAction, new FormData(formElement), "Domain added. Publish the TXT record, then check it.");
          formElement.reset();
        }}
      >
        <label>
          Domain
          <input name="domain" required placeholder="example.org.au" disabled={locked} />
        </label>
        <button type="submit" disabled={locked} title={denied ?? undefined}>
          Add domain
        </button>
      </form>
      {domains.length === 0 ? (
        <p className="muted">No sign-in domains yet.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>TXT record</th>
                <th>Status</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {domains.map((domain) => (
                <tr key={domain.id}>
                  <td className="mono">{domain.domain}</td>
                  <td>
                    <div className="mono">{domain.txtName}</div>
                    <div className="mono muted">{domain.txtValue}</div>
                  </td>
                  <td>
                    <span className={domain.verifiedAt ? "badge online" : "badge pending"}>
                      {domain.verifiedAt ? "Verified" : "Not verified"}
                    </span>
                    {domain.lastCheckedAt ? (
                      <div className="muted">
                        Checked {new Date(domain.lastCheckedAt).toLocaleString("en-AU")}
                      </div>
                    ) : null}
                  </td>
                  <td>
                    <div className="stack">
                      {domain.verifiedAt ? null : (
                        <button
                          type="button"
                          className="secondary"
                          disabled={locked}
                          onClick={() => {
                            const form = new FormData();
                            form.set("domainId", domain.id);
                            submit(verifyDomainAction, form, (data) =>
                              (data as { verified: boolean }).verified
                                ? `${domain.domain} is verified.`
                                : `No matching TXT record at ${domain.txtName} yet. DNS changes can take a while to appear.`,
                            );
                          }}
                        >
                          Check TXT record
                        </button>
                      )}
                      <button
                        type="button"
                        className="danger"
                        disabled={locked}
                        onClick={() => {
                          const form = new FormData();
                          form.set("domainId", domain.id);
                          submit(removeDomainAction, form, `${domain.domain} removed.`);
                        }}
                      >
                        Remove
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
