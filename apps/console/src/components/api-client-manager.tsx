"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { createApiClientAction, revokeApiClientAction } from "@/app/actions";
import { rotateApiClientAction, setApiClientSuspendedAction } from "@/app/settings/actions";
import type { ApiClient } from "@/lib/coord";
import { LocalTime } from "./ui/local-time";
import { Alert } from "./ui/alert";
import { StatusPill } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { SecretPanel } from "./ui/secret-panel";
import { Section } from "./ui/section";
import { EmptyRow, Table, Td } from "./ui/table";
import { toast, toastResult } from "./ui/toast";

const SCOPES = [
  ["devices:read", "Read devices"],
  ["devices:write", "Change devices"],
  ["keys:read", "Read join keys"],
  ["keys:write", "Create join keys"],
  ["routes:write", "Approve routes"],
  ["policy:write", "Change access policy"],
  ["dns:write", "Change DNS"],
  ["audit:read", "Read the audit log"],
  ["audit:export", "Export the audit log"],
  ["status:read", "Read status"],
  ["webhooks:read", "Read webhooks"],
  ["webhooks:write", "Change webhooks"],
] as const;

type Confirm = { client: ApiClient; kind: "revoke" | "rotate" | "suspend" };

export function ApiClientManager({
  clients,
  loadError = null,
}: {
  clients: ApiClient[];
  loadError?: string | null;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<string | null>(null);
  const [shownOnce, setShownOnce] = useState<{ name: string; token: string } | null>(null);
  const [errors, setErrors] = useState<{ name?: string; scopes?: string }>({});
  const [confirm, setConfirm] = useState<Confirm | null>(null);
  const active = clients.filter((client) => !client.revoked);

  function clientAction(
    key: string,
    work: () => Promise<{ ok: true } | { ok: false; error: string; ref?: string }>,
    done: string,
    after?: () => void,
  ) {
    setBusy(key);
    startTransition(async () => {
      const result = await work();
      setBusy(null);
      after?.();
      toastResult(result, { success: done });
      if (result.ok) router.refresh();
    });
  }

  const description =
    "Organisation-scoped credentials for the versioned admin API. They can't sign in to this console. Send X-BlakTail-Organisation with every request; their changes show in the audit log as api:<id>. Suspending or rotating stops the old secret and every access token minted from it.";
  if (loadError) {
    return (
      <Section id="automation" headingLevel={3} title="API clients and service users" description={description}>
        <Alert tone="error" title="API clients couldn't be loaded">
          {loadError}
        </Alert>
      </Section>
    );
  }

  return (
    <Section id="automation" headingLevel={3} title="API clients and service users" description={description}>
      {shownOnce ? (
        <SecretPanel
          title={`Copy the token for ${shownOnce.name} now`}
          label="API token"
          secret={shownOnce.token}
          description="This is the only time it's shown; only a hash is stored. Put it straight into your automation's secret store."
          onDone={() => setShownOnce(null)}
        />
      ) : null}
      <Table label="API clients" mobile="stack">
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Token prefix</th>
            <th scope="col">Scopes</th>
            <th scope="col">State</th>
            <th scope="col">
              <span className="visually-hidden">Actions</span>
            </th>
          </tr>
        </thead>
        <tbody>
          {clients.length === 0 ? (
            <EmptyRow colSpan={5}>
              {loadError ? "API clients couldn't be loaded." : "No API clients yet. Create one below for scripts or CI."}
            </EmptyRow>
          ) : (
            clients.map((client) => (
              <tr key={client.id}>
                <Td label="Name">{client.name}</Td>
                <Td label="Token prefix" className="mono">
                  {client.token_prefix}
                </Td>
                <Td label="Scopes">
                  <span className="mono cell-break">{client.scopes.join(", ")}</span>
                </Td>
                <Td label="State">
                  <StatusPill tone={client.revoked ? "muted" : client.suspended ? "warning" : "success"}>
                    {client.revoked ? "Revoked" : client.suspended ? "Suspended" : "Active"}
                  </StatusPill>
                  {client.expires_at ? <span className="cell-sub">Expires <LocalTime value={client.expires_at} dateOnly /></span> : null}
                  {client.rotated_at ? <span className="cell-sub">Rotated <LocalTime value={client.rotated_at} dateOnly /></span> : null}
                </Td>
                <Td>
                  {client.revoked ? null : (
                    <div className="cell-actions">
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={pending}
                        onClick={() => setConfirm({ client, kind: "rotate" })}
                      >
                        Rotate secret
                      </Button>
                      {client.suspended ? (
                        <Button
                          size="sm"
                          variant="secondary"
                          loading={busy === client.id}
                          disabled={pending}
                          onClick={() => {
                            const form = new FormData();
                            form.set("clientId", client.id);
                            form.set("suspended", "false");
                            clientAction(client.id, () => setApiClientSuspendedAction(form), `${client.name} resumed`);
                          }}
                        >
                          Resume
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          variant="secondary"
                          disabled={pending}
                          onClick={() => setConfirm({ client, kind: "suspend" })}
                        >
                          Suspend
                        </Button>
                      )}
                      <Button
                        size="sm"
                        variant="quiet-danger"
                        disabled={pending}
                        onClick={() => setConfirm({ client, kind: "revoke" })}
                      >
                        Revoke
                      </Button>
                    </div>
                  )}
                </Td>
              </tr>
            ))
          )}
        </tbody>
      </Table>

      <details className="form-disclosure" open={active.length === 0 && !loadError}>
        <summary>Create an API client</summary>
        <form
          className="ui-form"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            const formElement = event.currentTarget;
            const form = new FormData(formElement);
            const name = String(form.get("name") ?? "").trim();
            const next: typeof errors = {};
            if (!name) next.name = "Name the client, for example terraform-ci.";
            if (form.getAll("scopes").length === 0) next.scopes = "Choose at least one scope.";
            setErrors(next);
            if (Object.keys(next).length) return;
            setShownOnce(null);
            setBusy("create");
            startTransition(async () => {
              const result = await createApiClientAction(form);
              setBusy(null);
              if (!result.ok) {
                toastResult(result);
                return;
              }
              formElement.reset();
              setShownOnce({ name, token: result.data.token });
              toast.success("API client created");
              router.refresh();
            });
          }}
        >
          <FormField label="Name" required error={errors.name}>
            <input name="name" maxLength={64} autoComplete="off" placeholder="terraform-ci" />
          </FormField>
          <fieldset className="check-grid" aria-describedby={errors.scopes ? "scopes-error" : undefined}>
            <legend>Scopes</legend>
            {SCOPES.map(([scope, label]) => (
              <label key={scope} className="check-option">
                <input
                  type="checkbox"
                  name="scopes"
                  value={scope}
                  defaultChecked={scope === "status:read" || scope === "devices:read"}
                />
                <span>
                  {label}
                  <span className="muted mono">{scope}</span>
                </span>
              </label>
            ))}
          </fieldset>
          {errors.scopes ? (
            <p id="scopes-error" className="ui-field-error" role="alert">
              {errors.scopes}
            </p>
          ) : null}
          <div className="actions">
            <Button type="submit" loading={busy === "create"} loadingLabel="Creating…" disabled={pending}>
              Create API client
            </Button>
          </div>
        </form>
      </details>

      <ConfirmDialog
        open={confirm !== null}
        title={
          confirm?.kind === "revoke"
            ? "Revoke this API client?"
            : confirm?.kind === "rotate"
              ? "Rotate the secret?"
              : "Suspend this API client?"
        }
        description={
          confirm
            ? confirm.kind === "revoke"
              ? `${confirm.client.name} stops working for good, along with every access token minted from it. This can't be undone.`
              : confirm.kind === "rotate"
                ? `The current secret for ${confirm.client.name} stops working on its next request. You'll get a new secret to copy once.`
                : `${confirm.client.name} stops working until you resume it.`
            : null
        }
        confirmText={confirm?.kind === "revoke" ? confirm.client.name : undefined}
        confirmLabel={confirm?.kind === "revoke" ? "Revoke client" : confirm?.kind === "rotate" ? "Rotate secret" : "Suspend"}
        tone={confirm?.kind === "rotate" ? "primary" : "danger"}
        pending={pending}
        onCancel={() => setConfirm(null)}
        onConfirm={() => {
          if (!confirm) return;
          const { client, kind } = confirm;
          const form = new FormData();
          form.set("clientId", client.id);
          if (kind === "rotate") {
            setShownOnce(null);
            startTransition(async () => {
              const result = await rotateApiClientAction(form);
              setConfirm(null);
              if (!result.ok) {
                toastResult(result);
                return;
              }
              setShownOnce({ name: client.name, token: result.data.token });
              toast.success("Secret rotated", { description: `The old secret for ${client.name} no longer works.` });
              router.refresh();
            });
            return;
          }
          if (kind === "suspend") form.set("suspended", "true");
          clientAction(
            client.id,
            () => (kind === "revoke" ? revokeApiClientAction(form) : setApiClientSuspendedAction(form)),
            kind === "revoke" ? `${client.name} revoked` : `${client.name} suspended`,
            () => setConfirm(null),
          );
        }}
      />
    </Section>
  );
}
