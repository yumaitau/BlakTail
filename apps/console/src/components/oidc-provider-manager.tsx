"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Copy } from "lucide-react";
import { upsertOidcProviderAction } from "@/app/actions";
import { deleteOidcProviderAction } from "@/app/settings/actions";
import { StatusPill } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { Section } from "./ui/section";
import { toast, toastResult } from "./ui/toast";

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

type Field = "issuer" | "clientId" | "clientSecret";

function issuerHost(issuer: string): string {
  try {
    return new URL(issuer).host;
  } catch {
    return issuer;
  }
}

export function OidcProviderManager({ providers }: { providers: IdentityProviderSummary[] }) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [errors, setErrors] = useState<Partial<Record<Field, string>>>({});
  const [deleting, setDeleting] = useState(false);
  const current = providers[0];

  return (
    <Section
      id="sso"
      headingLevel={3}
      title="Single sign-on"
      description="Your organisation's OpenID Connect identity provider (authorisation code with PKCE). The client secret is encrypted at rest and never shown again. Password owners keep their break-glass sign-in."
      actions={
        current ? (
          <StatusPill tone={current.enabled ? "success" : "muted"}>
            {current.enabled ? "Enabled" : "Saved, not enabled"}
          </StatusPill>
        ) : (
          <StatusPill tone="muted">Not set up</StatusPill>
        )
      }
    >
      {current ? (
        <div className="form-row">
          <FormField label="Callback URL" hint="Register this redirect URI with your identity provider.">
            <input className="mono" readOnly value={current.callbackUrl} onFocus={(event) => event.currentTarget.select()} />
          </FormField>
          <Button
            variant="secondary"
            icon={<Copy aria-hidden="true" size={16} />}
            onClick={() => {
              void navigator.clipboard?.writeText(current.callbackUrl).then(
                () => toast.success("Callback URL copied"),
                () => toast.error("Couldn't copy. Select the URL and copy it manually."),
              );
            }}
          >
            Copy
          </Button>
        </div>
      ) : null}
      <form
        className="ui-form"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          const next: Partial<Record<Field, string>> = {};
          const issuer = String(form.get("issuer") ?? "").trim();
          if (!/^https:\/\/[^\s/]+/u.test(issuer)) next.issuer = "Enter the issuer's HTTPS address, like https://login.example.org.au.";
          if (!String(form.get("clientId") ?? "").trim()) next.clientId = "Enter the client ID from your identity provider.";
          if (String(form.get("clientSecret") ?? "").trim().length < 16) {
            next.clientSecret = current
              ? "Enter the client secret again (at least 16 characters) to save changes."
              : "Enter the client secret (at least 16 characters).";
          }
          setErrors(next);
          if (Object.keys(next).length) return;
          startTransition(async () => {
            const result = await upsertOidcProviderAction(form);
            if (!result.ok) {
              toastResult(result);
              return;
            }
            toast.success("Identity provider saved", { description: "The client secret won't be shown again." });
            router.refresh();
          });
        }}
      >
        <FormField label="Issuer" required error={errors.issuer}>
          <input
            name="issuer"
            type="url"
            placeholder="https://login.example.org.au"
            defaultValue={current?.issuer ?? ""}
          />
        </FormField>
        <div className="form-grid">
          <FormField label="Client ID" required hint="From your identity provider's app registration." error={errors.clientId}>
            <input name="clientId" defaultValue={current?.clientId ?? ""} autoComplete="off" />
          </FormField>
          <FormField
            label="Client secret"
            required
            hint={current ? "Stored encrypted. Enter it again to save any change." : "Stored encrypted and never shown again."}
            error={errors.clientSecret}
          >
            <input name="clientSecret" type="password" autoComplete="new-password" />
          </FormField>
        </div>
        <div className="form-grid">
          <FormField label="Allowed email domains" hint="Optional. Separate with commas.">
            <input
              name="allowDomains"
              defaultValue={current?.allowDomainsJson.join(", ") ?? ""}
              placeholder="example.org.au"
            />
          </FormField>
          <FormField label="Allowed provider groups" hint="Optional. Separate with commas.">
            <input
              name="allowGroups"
              defaultValue={current?.allowGroupsJson.join(", ") ?? ""}
              placeholder="staff, rangers"
            />
          </FormField>
        </div>
        <label className="check-option">
          <input type="checkbox" name="enabled" value="true" defaultChecked={current?.enabled ?? false} />
          <span>Enable single sign-on for this organisation</span>
        </label>
        <label className="check-option">
          <input type="checkbox" name="jitMembership" value="true" defaultChecked={current?.jitMembership ?? false} />
          <span>
            Add allowed people automatically on their first sign-in
            <span className="muted">They join as members. Owners can change roles afterwards.</span>
          </span>
        </label>
        <div className="actions">
          <Button type="submit" loading={pending && !deleting} loadingLabel="Saving…" disabled={pending}>
            {current ? "Save provider" : "Add provider"}
          </Button>
          {current ? (
            <Button variant="quiet-danger" disabled={pending} onClick={() => setDeleting(true)}>
              Delete provider
            </Button>
          ) : null}
        </div>
      </form>
      {current ? (
        <ConfirmDialog
          open={deleting}
          title="Delete the identity provider?"
          description={`Nobody can sign in to this organisation through ${issuerHost(current.issuer)} any more, and existing single sign-on links are removed. Memberships stay; people sign in with a password or a new provider.`}
          confirmText={issuerHost(current.issuer)}
          confirmLabel="Delete provider"
          pending={pending}
          onCancel={() => setDeleting(false)}
          onConfirm={() => {
            const form = new FormData();
            form.set("providerId", current.id);
            startTransition(async () => {
              const result = await deleteOidcProviderAction(form);
              setDeleting(false);
              toastResult(result, { success: "Identity provider deleted" });
              if (result.ok) router.refresh();
            });
          }}
        />
      ) : null}
    </Section>
  );
}
