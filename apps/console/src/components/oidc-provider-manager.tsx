"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { upsertOidcProviderAction } from "@/app/actions";

export type IdentityProviderSummary = {
  id: string;
  issuer: string;
  clientId: string;
  enabled: boolean;
  jitMembership: boolean;
  defaultRole: string;
  allowDomainsJson: string[];
  allowGroupsJson: string[];
  callbackUrl: string;
};

export function OidcProviderManager({
  providers,
}: {
  providers: IdentityProviderSummary[];
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const current = providers[0];

  return (
    <div className="panel stack">
      <div>
        <h2>Organisation identity provider</h2>
        <p className="muted">
          Authorization Code + PKCE. The client secret is encrypted at rest and
          never shown again. Break-glass owners keep their password accounts.
        </p>
      </div>
      <label>
        Callback URL
        <input className="mono" readOnly value={current?.callbackUrl ?? ""} />
      </label>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          setError(null);
          setSaved(false);
          startTransition(async () => {
            const result = await upsertOidcProviderAction(form);
            if (!result.ok) {
              setError(result.error);
              return;
            }
            setSaved(true);
            router.refresh();
          });
        }}
      >
        <label>
          Issuer
          <input
            name="issuer"
            type="url"
            required
            placeholder="https://idp.example"
            defaultValue={current?.issuer ?? ""}
          />
        </label>
        <label>
          Client ID
          <input name="clientId" required defaultValue={current?.clientId ?? ""} />
        </label>
        <label>
          Client secret
          <input
            name="clientSecret"
            type="password"
            required
            minLength={16}
            autoComplete="new-password"
            placeholder={current ? "Enter a new secret to rotate" : ""}
          />
        </label>
        <label>
          Allowed email domains (comma-separated, optional)
          <input
            name="allowDomains"
            defaultValue={current?.allowDomainsJson.join(", ") ?? ""}
            placeholder="org.example"
          />
        </label>
        <label>
          Allowed identity-provider groups (comma-separated, optional)
          <input
            name="allowGroups"
            defaultValue={current?.allowGroupsJson.join(", ") ?? ""}
            placeholder="staff, rangers"
          />
        </label>
        <label className="route-option">
          <input
            type="checkbox"
            name="enabled"
            value="true"
            defaultChecked={current?.enabled ?? false}
          />
          Enable this provider
        </label>
        <label className="route-option">
          <input
            type="checkbox"
            name="jitMembership"
            value="true"
            defaultChecked={current?.jitMembership ?? false}
          />
          Allow just-in-time membership for allowed identities
        </label>
        <button type="submit" disabled={pending}>
          {pending ? "Saving…" : "Save provider"}
        </button>
      </form>
      {saved ? <p className="muted">Provider saved. The secret is not shown again.</p> : null}
      {error ? <p className="error">{error}</p> : null}
    </div>
  );
}
