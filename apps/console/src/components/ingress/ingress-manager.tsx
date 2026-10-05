"use client";

import { useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  createRouteAction,
  deleteRouteAction,
  emergencyDisableAction,
  setIngressDesignationAction,
  setIngressEnabledAction,
  setRouteEnabledAction,
} from "@/app/ingress/actions";
import type { ActionResult } from "@/app/actions";
import type {
  IngressNode,
  IngressWorkspace,
  PublicRoute,
  RouteStatus,
} from "@/lib/coord-ingress";
import { EmptyState } from "../empty-state";
import { Alert } from "../ui/alert";
import { StatusPill, type BadgeTone } from "../ui/badge";
import { Button } from "../ui/button";
import { ConfirmDialog } from "../ui/confirm-dialog";
import { FormField } from "../ui/form-field";
import { LocalTime } from "../ui/local-time";
import { MonoValue } from "../ui/mono-value";
import { PermissionNotice } from "../ui/permission-notice";
import { Section } from "../ui/section";
import { Table, Td } from "../ui/table";
import { toastResult } from "../ui/toast";

type Option = { id: string; label: string };
type Run = (
  key: string,
  action: () => Promise<ActionResult>,
  messages: { success: string; description?: string },
  after?: (result: ActionResult) => void,
) => void;

const STATUS: Record<RouteStatus, { label: string; tone: BadgeTone; detail: string }> = {
  active: { label: "Live on the Internet", tone: "danger", detail: "An online ingress serves this route." },
  organisation_disabled: {
    label: "Organisation off",
    tone: "muted",
    detail: "Public ingress is turned off for this organisation, so nothing is served.",
  },
  emergency_disabled: {
    label: "Emergency disabled",
    tone: "danger",
    detail: "Withdrawn from every ingress. An owner must re-enable it.",
  },
  disabled: { label: "Disabled", tone: "muted", detail: "Not served." },
  target_unavailable: {
    label: "Target unavailable",
    tone: "danger",
    detail: "The target device or service is revoked, suspended, expired or disabled.",
  },
  target_unsupported: {
    label: "Target unsupported",
    tone: "danger",
    detail: "The ingress reaches targets over plain HTTP inside the overlay; the service must use HTTP.",
  },
  target_is_ingress: {
    label: "Target is the ingress",
    tone: "danger",
    detail: "Choose a different device from the ingress host.",
  },
  blocked_by_policy: {
    label: "Blocked by policy",
    tone: "danger",
    detail: "Access policy doesn't let the ingress device reach this target port, so it isn't served. A public URL never widens policy.",
  },
  ingress_offline: {
    label: "Ingress offline",
    tone: "warning",
    detail: "Allowed, but no ingress has fetched its configuration recently.",
  },
  ingress_not_capable: {
    label: "Ingress not enabled",
    tone: "warning",
    detail: "Run blaktaild up --public-ingress on the ingress host.",
  },
  ingress_not_designated: {
    label: "Ingress not designated",
    tone: "warning",
    detail: "An owner must designate this device as an ingress host before it receives routes.",
  },
  no_ingress_node: {
    label: "No ingress host",
    tone: "warning",
    detail: "Enrol an onshore host with blaktaild up --public-ingress and run blaktail-ingress there.",
  },
};

/** Whole days from `now` (the server's render time, so hydration matches). */
function days(seconds: number, now: number): number {
  return Math.floor((seconds - now) / 86_400);
}

export function IngressManager({
  workspace,
  devices,
  services,
  ownerReason,
  canEmergencyDisable,
  now,
}: {
  workspace: IngressWorkspace;
  devices: Option[];
  services: Option[];
  ownerReason: string | null;
  canEmergencyDisable: boolean;
  /** Unix seconds when the page was rendered; the reference for "N days". */
  now: number;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<string | null>(null);
  const isOwner = ownerReason === null;

  const run: Run = (key, action, messages, after) => {
    setBusy(key);
    startTransition(async () => {
      const result = await action();
      setBusy(null);
      toastResult(result, { success: messages.success, successDescription: messages.description });
      after?.(result);
      if (result.ok) router.refresh();
    });
  };
  const shared = { pending, busy, run };

  return (
    <>
      {!isOwner ? (
        <PermissionNotice reason={ownerReason ?? ""}>
          {canEmergencyDisable
            ? "You can still emergency-disable a live route."
            : "Owners, admins and network admins can emergency-disable a route."}
        </PermissionNotice>
      ) : null}
      <SettingsPanel workspace={workspace} isOwner={isOwner} {...shared} />
      <Section
        id="routes"
        className="public-panel"
        title="Public routes"
        description={`Each route answers one public hostname and forwards only to its one published target over the overlay. The ingress drops a route within ${workspace.stale_after_secs} seconds of losing contact with the coordinator, and an emergency disable reaches it on its next poll.`}
        actions={<StatusPill tone="danger">PUBLIC</StatusPill>}
      >
        {workspace.routes.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No public routes"
            body="Nothing from this organisation is on the Internet through BlakTail."
          />
        ) : (
          <ul className="stack public-routes">
            {workspace.routes.map((route) => (
              <RouteCard
                key={route.id}
                route={route}
                isOwner={isOwner}
                canEmergencyDisable={canEmergencyDisable}
                now={now}
                {...shared}
              />
            ))}
          </ul>
        )}
      </Section>
      {isOwner ? (
        <CreateRoute
          enabled={workspace.settings.enabled}
          devices={devices}
          services={services}
          {...shared}
        />
      ) : null}
      <IngressHosts workspace={workspace} isOwner={isOwner} {...shared} />
    </>
  );
}

function SettingsPanel({
  workspace,
  isOwner,
  pending,
  busy,
  run,
}: {
  workspace: IngressWorkspace;
  isOwner: boolean;
  pending: boolean;
  busy: string | null;
  run: Run;
}) {
  const [confirm, setConfirm] = useState("");
  const [contact, setContact] = useState(workspace.settings.abuse_contact);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [turningOff, setTurningOff] = useState(false);
  const { enabled } = workspace.settings;
  return (
    <Section
      id="settings"
      className={enabled ? "public-panel" : undefined}
      title="Organisation setting"
      description="Your organisation runs the ingress host and chooses its DNS, certificate authority and monitoring. BlakTail doesn't operate a shared ingress and can't vouch for where those providers keep data."
      actions={
        enabled ? (
          <StatusPill tone="danger">Public ingress on</StatusPill>
        ) : (
          <StatusPill tone="muted">Public ingress off</StatusPill>
        )
      }
    >
      {workspace.settings.abuse_contact ? (
        <p className="muted">
          Abuse contact: <MonoValue value={workspace.settings.abuse_contact} />
        </p>
      ) : null}
      {isOwner ? (
        enabled ? (
          <div className="ui-form-actions">
            <Button variant="quiet-danger" disabled={pending} onClick={() => setTurningOff(true)}>
              Turn off public ingress
            </Button>
            <span className="muted">Withdraws every route from every ingress.</span>
          </div>
        ) : (
          <form
            className="ui-form"
            noValidate
            onSubmit={(event) => {
              event.preventDefault();
              const form = new FormData(event.currentTarget);
              form.set("enabled", "true");
              if (!contact.trim()) {
                setFieldErrors({ abuseContact: "Enter an abuse contact email or https:// URL." });
                return;
              }
              setFieldErrors({});
              run(
                "settings",
                () => setIngressEnabledAction(form),
                {
                  success: "Public ingress allowed",
                  description: "Owners can now publish routes. Nothing is public yet.",
                },
                (result) => {
                  if (result.ok) setConfirm("");
                  else setFieldErrors(result.fieldErrors ?? {});
                },
              );
            }}
          >
            <p className="ui-field-hint">
              Turning this on lets owners publish routes. It doesn&apos;t publish anything by
              itself.
            </p>
            <FormField
              label="Abuse contact"
              hint="An email address or https:// URL people can report abuse to."
              required
              error={fieldErrors.abuseContact}
              className="field-md"
            >
              <input
                name="abuseContact"
                maxLength={200}
                value={contact}
                onChange={(event) => setContact(event.target.value)}
                disabled={pending}
              />
            </FormField>
            <FormField label="Type PUBLIC to confirm" required className="field-sm">
              <input
                name="confirm"
                autoComplete="off"
                value={confirm}
                onChange={(event) => setConfirm(event.target.value)}
                disabled={pending}
              />
            </FormField>
            <div className="ui-form-actions">
              <Button
                type="submit"
                variant="danger"
                loading={busy === "settings"}
                loadingLabel="Allowing…"
                disabled={pending || confirm !== "PUBLIC"}
              >
                Allow public ingress
              </Button>
            </div>
          </form>
        )
      ) : null}
      <ConfirmDialog
        open={turningOff}
        title="Turn off public ingress?"
        description="Every route is withdrawn from every ingress on its next poll. Routes stay configured, so you can turn ingress on again later."
        confirmLabel="Turn off"
        pending={busy === "settings"}
        onCancel={() => setTurningOff(false)}
        onConfirm={() => {
          const form = new FormData();
          form.set("enabled", "false");
          form.set("abuseContact", contact);
          run(
            "settings",
            () => setIngressEnabledAction(form),
            { success: "Public ingress turned off", description: "Every route is withdrawn." },
            () => setTurningOff(false),
          );
        }}
      />
    </Section>
  );
}

function RouteCard({
  route,
  isOwner,
  canEmergencyDisable,
  now,
  pending,
  busy,
  run,
}: {
  route: PublicRoute;
  isOwner: boolean;
  canEmergencyDisable: boolean;
  now: number;
  pending: boolean;
  busy: string | null;
  run: Run;
}) {
  const status = STATUS[route.status] ?? STATUS.disabled;
  const [dialog, setDialog] = useState<"emergency" | "enable" | "delete" | null>(null);
  const [reason, setReason] = useState("");
  const live = route.enabled && route.emergency_disabled_at === null;
  const key = (kind: string) => `${kind}:${route.id}`;
  const close = () => {
    setDialog(null);
    setReason("");
  };
  return (
    <li className="public-route stack">
      <div className="row public-route-head">
        <StatusPill tone="danger">PUBLIC</StatusPill>
        <MonoValue value={`https://${route.fqdn}`} copy copyLabel="Copy public address" />
        <StatusPill tone={status.tone}>{status.label}</StatusPill>
      </div>
      <p className="muted">{status.detail}</p>
      <dl className="public-facts">
        <div>
          <dt>Target</dt>
          <dd>
            {route.target_node_name ?? "Removed device"} port{" "}
            <span className="mono">{route.target_port}</span>
            {route.target_service_id ? " (private service)" : ""}
          </dd>
        </div>
        <div>
          <dt>Sign-in</dt>
          <dd>
            {route.auth_mode === "oidc"
              ? `Organisation sign-in${route.allowed_email_domains.length ? ` (${route.allowed_email_domains.join(", ")})` : ""}`
              : "None: anyone on the Internet"}
          </dd>
        </div>
        <div>
          <dt>Who can connect</dt>
          <dd>
            {route.allowed_source_cidrs.length > 0
              ? route.allowed_source_cidrs.join(", ")
              : "Any Internet address"}
          </dd>
        </div>
        <div>
          <dt>Certificate</dt>
          <dd>
            {route.tls_mode === "acme_http01"
              ? "ACME HTTP-01 on the ingress"
              : "Operator files on the ingress"}
          </dd>
        </div>
        <div>
          <dt>Limits</dt>
          <dd>
            {route.limits.rate_limit_per_minute}/min per client,{" "}
            {Math.round(route.limits.max_body_bytes / 1024 / 1024)} MiB bodies,{" "}
            {route.limits.max_connections} connections, logs kept{" "}
            {route.limits.log_retention_days} days
          </dd>
        </div>
      </dl>
      {route.ingress.length > 0 ? (
        <Table label={`Ingress hosts serving ${route.fqdn}`} mobile="stack">
          <thead>
            <tr>
              <th scope="col">Ingress host</th>
              <th scope="col">State</th>
              <th scope="col">Certificate</th>
            </tr>
          </thead>
          <tbody>
            {route.ingress.map((ingress) => {
              const state = STATUS[ingress.state] ?? STATUS.disabled;
              return (
                <tr key={ingress.node_id}>
                  <Td label="Ingress host">{ingress.node_name}</Td>
                  <Td label="State">
                    <StatusPill tone={state.tone}>{state.label}</StatusPill>
                  </Td>
                  <Td label="Certificate">
                    <div>
                      {ingress.certificate_not_after ? (
                        <span
                          className={days(ingress.certificate_not_after, now) < 14 ? "error" : undefined}
                        >
                          Expires <LocalTime value={ingress.certificate_not_after} /> (
                          {days(ingress.certificate_not_after, now)} days)
                        </span>
                      ) : (
                        <span className="muted">Not reported</span>
                      )}
                      {ingress.last_error ? (
                        <div className="cell-sub error">{ingress.last_error}</div>
                      ) : null}
                    </div>
                  </Td>
                </tr>
              );
            })}
          </tbody>
        </Table>
      ) : null}
      {route.emergency_disabled_at ? (
        <Alert tone="error" title="Emergency disabled">
          <LocalTime value={route.emergency_disabled_at} />
          {route.emergency_disabled_by ? ` by ${route.emergency_disabled_by}. ` : ". "}
          {route.emergency_reason ? `Reason: ${route.emergency_reason}` : null}
        </Alert>
      ) : null}
      {canEmergencyDisable || isOwner ? (
        <div className="ui-form-actions">
          {canEmergencyDisable && live ? (
            <Button variant="danger" disabled={pending} onClick={() => setDialog("emergency")}>
              Emergency disable
            </Button>
          ) : null}
          {isOwner && live ? (
            <Button
              variant="secondary"
              disabled={pending}
              loading={busy === key("disable")}
              loadingLabel="Disabling…"
              onClick={() =>
                run(
                  key("disable"),
                  () => setRouteEnabledAction(route.id, route.revision, false, ""),
                  { success: "Route disabled", description: `${route.fqdn} is no longer served.` },
                )
              }
            >
              Disable
            </Button>
          ) : null}
          {isOwner && !live ? (
            <Button variant="danger" disabled={pending} onClick={() => setDialog("enable")}>
              Re-enable publicly
            </Button>
          ) : null}
          {isOwner ? (
            <Button variant="quiet-danger" disabled={pending} onClick={() => setDialog("delete")}>
              Delete
            </Button>
          ) : null}
        </div>
      ) : null}
      <ConfirmDialog
        open={dialog === "emergency"}
        title="Emergency disable this route?"
        description={`${route.fqdn} is withdrawn from every ingress on its next poll. Only an owner can re-enable it.`}
        confirmLabel="Emergency disable"
        pending={busy === key("emergency")}
        onCancel={close}
        onConfirm={() =>
          run(
            key("emergency"),
            () => emergencyDisableAction(route.id, reason),
            { success: "Route emergency disabled", description: `${route.fqdn} is being withdrawn.` },
            close,
          )
        }
      >
        <FormField label="Reason" hint="Recorded in the audit log. Optional, up to 200 characters.">
          <textarea
            rows={2}
            maxLength={200}
            value={reason}
            onChange={(event) => setReason(event.target.value)}
          />
        </FormField>
      </ConfirmDialog>
      <ConfirmDialog
        open={dialog === "enable"}
        title="Put this route back on the Internet?"
        description={`Anyone who can reach the ingress can reach https://${route.fqdn}, subject to its sign-in and limits.`}
        confirmText={route.fqdn}
        confirmLabel="Re-enable publicly"
        pending={busy === key("enable")}
        onCancel={close}
        onConfirm={() =>
          run(
            key("enable"),
            () => setRouteEnabledAction(route.id, route.revision, true, route.fqdn),
            { success: "Route re-enabled", description: `${route.fqdn} is public again.` },
            close,
          )
        }
      />
      <ConfirmDialog
        open={dialog === "delete"}
        title="Delete public route"
        description={`https://${route.fqdn} is withdrawn from every ingress and its settings are removed. This can't be undone.`}
        confirmText={route.fqdn}
        confirmLabel="Delete route"
        pending={busy === key("delete")}
        onCancel={close}
        onConfirm={() =>
          run(
            key("delete"),
            () => deleteRouteAction(route.id),
            { success: "Route deleted", description: `${route.fqdn} is no longer public.` },
            close,
          )
        }
      />
    </li>
  );
}

function CreateRoute({
  enabled,
  devices,
  services,
  pending,
  busy,
  run,
}: {
  enabled: boolean;
  devices: Option[];
  services: Option[];
  pending: boolean;
  busy: string | null;
  run: Run;
}) {
  const formRef = useRef<HTMLFormElement>(null);
  const [fqdn, setFqdn] = useState("");
  const [confirm, setConfirm] = useState("");
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [target, setTarget] = useState(
    services[0] ? `service:${services[0].id}` : devices[0] ? `node:${devices[0].id}` : "",
  );
  const [auth, setAuth] = useState("none");
  const disabled = pending || !enabled;
  const normalised = fqdn.trim().toLowerCase().replace(/\.$/, "");
  const confirmed =
    normalised !== "" && confirm.trim().toLowerCase().replace(/\.$/, "") === normalised;
  return (
    <Section
      id="create"
      className="public-panel"
      title="Publish a route"
      description="Point the hostname's DNS at your ingress host and place its certificate there (or choose ACME). Access policy must also let the ingress device reach the target."
      actions={<StatusPill tone="danger">PUBLIC</StatusPill>}
    >
      {!enabled ? (
        <Alert tone="info" title="Public ingress is off">
          Allow public ingress for the organisation above before publishing a route.
        </Alert>
      ) : null}
      <form
        ref={formRef}
        className="ui-form wide"
        noValidate
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          if (!normalised) {
            setFieldErrors({ fqdn: "Enter the public hostname." });
            return;
          }
          if (!confirmed) {
            setFieldErrors({ confirmFqdn: "Type the same hostname again to confirm." });
            return;
          }
          setFieldErrors({});
          run(
            "create",
            () => createRouteAction(form),
            { success: "Route published", description: `https://${normalised} is now public.` },
            (result) => {
              if (!result.ok) {
                setFieldErrors(result.fieldErrors ?? {});
                return;
              }
              formRef.current?.reset();
              setFqdn("");
              setConfirm("");
            },
          );
        }}
      >
        <fieldset className="ui-fieldset" disabled={disabled}>
          <legend>Hostname and target</legend>
          <div className="ui-form-grid">
            <FormField label="Public hostname" required error={fieldErrors.fqdn}>
              <input
                name="fqdn"
                maxLength={253}
                placeholder="bookings.example.org.au"
                autoComplete="off"
                spellCheck={false}
                value={fqdn}
                onChange={(event) => setFqdn(event.target.value)}
              />
            </FormField>
            <FormField label="Target" required>
              <select
                name="target"
                value={target}
                onChange={(event) => setTarget(event.target.value)}
                disabled={devices.length === 0 && services.length === 0}
              >
                {services.length > 0 ? (
                  <optgroup label="Private services (HTTP)">
                    {services.map((service) => (
                      <option key={service.id} value={`service:${service.id}`}>
                        {service.label}
                      </option>
                    ))}
                  </optgroup>
                ) : null}
                <optgroup label="Device and port">
                  {devices.map((device) => (
                    <option key={device.id} value={`node:${device.id}`}>
                      {device.label}
                    </option>
                  ))}
                </optgroup>
              </select>
            </FormField>
          </div>
          <div className="ui-form-grid">
            {target.startsWith("node:") ? (
              <FormField label="Target HTTP port on the device" required error={fieldErrors.port}>
                <input name="port" type="number" min={1} max={65535} defaultValue={8080} />
              </FormField>
            ) : null}
            <FormField label="Certificate" className="field-md">
              <select name="tlsMode" defaultValue="operator_files">
                <option value="operator_files">Operator files on the ingress host</option>
                <option value="acme_http01">ACME HTTP-01 from the ingress host</option>
              </select>
            </FormField>
          </div>
        </fieldset>
        <fieldset className="ui-fieldset" disabled={disabled}>
          <legend>Who can use it</legend>
          <div className="ui-form-grid">
            <FormField label="Sign-in" className="field-md">
              <select name="authMode" value={auth} onChange={(event) => setAuth(event.target.value)}>
                <option value="none">None: anyone on the Internet</option>
                <option value="oidc">Organisation sign-in (OIDC)</option>
              </select>
            </FormField>
            {auth === "oidc" ? (
              <FormField
                label="Allowed email domains"
                hint="Optional. Comma-separated."
                error={fieldErrors.allowedDomains}
              >
                <input name="allowedDomains" placeholder="example.org.au" />
              </FormField>
            ) : null}
          </div>
          <FormField
            label="Allowed client networks"
            hint="Optional. Comma-separated CIDRs. Leave blank to allow any Internet address."
            error={fieldErrors.allowedSources}
            className="field-md"
          >
            <input name="allowedSources" className="mono" placeholder="203.0.113.0/24" />
          </FormField>
        </fieldset>
        <fieldset className="ui-fieldset" disabled={disabled}>
          <legend>Limits</legend>
          <div className="ui-form-grid">
            <FormField label="Requests per minute per client">
              <input name="rate" type="number" min={1} max={60000} defaultValue={600} />
            </FormField>
            <FormField label="Largest request body (MiB)">
              <input name="maxBodyMiB" type="number" min={0} max={100} defaultValue={10} />
            </FormField>
            <FormField label="Concurrent connections">
              <input name="maxConnections" type="number" min={1} max={4096} defaultValue={256} />
            </FormField>
            <FormField label="Keep access logs (days)">
              <input name="retention" type="number" min={1} max={365} defaultValue={30} />
            </FormField>
          </div>
        </fieldset>
        <FormField
          label="Type the hostname again to confirm"
          hint="It will be reachable from the Internet as soon as an ingress picks it up."
          required
          error={fieldErrors.confirmFqdn}
          className="field-md"
        >
          <input
            name="confirmFqdn"
            autoComplete="off"
            spellCheck={false}
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            disabled={disabled}
          />
        </FormField>
        <div className="ui-form-actions">
          <Button
            type="submit"
            variant="danger"
            loading={busy === "create"}
            loadingLabel="Publishing…"
            disabled={disabled || !confirmed || target === ""}
          >
            Publish to the Internet
          </Button>
        </div>
      </form>
    </Section>
  );
}

function IngressHosts({
  workspace,
  isOwner,
  pending,
  busy,
  run,
}: {
  workspace: IngressWorkspace;
  isOwner: boolean;
  pending: boolean;
  busy: string | null;
  run: Run;
}) {
  const [designating, setDesignating] = useState<IngressNode | null>(null);
  return (
    <Section
      id="hosts"
      title="Ingress hosts"
      description={
        <>
          Devices running <span className="mono">blaktaild up --public-ingress</span>. Reporting
          the capability isn&apos;t enough: an owner must designate a device before it receives
          any route, because it learns every route&apos;s overlay target and sign-in allowlist.
          Online means it fetched configuration in the last 90 seconds.
        </>
      }
    >
      {workspace.ingress_nodes.length === 0 ? (
        <EmptyState
          compact
          headingLevel={3}
          title="No ingress host yet"
          body="Enrol an onshore host and run blaktaild up --public-ingress there. It shows here for an owner to designate."
        />
      ) : (
        <Table label="Ingress hosts" mobile="stack">
          <thead>
            <tr>
              <th scope="col">Device</th>
              <th scope="col">State</th>
              <th scope="col">Last configuration fetch</th>
              <th scope="col">
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {workspace.ingress_nodes.map((node) => (
              <tr key={node.id}>
                <Td label="Device">{node.name}</Td>
                <Td label="State">
                  <div>
                    {!node.capable ? (
                      <StatusPill tone="warning">Capability off</StatusPill>
                    ) : !node.designated ? (
                      <StatusPill tone="warning">Not designated</StatusPill>
                    ) : node.online ? (
                      <StatusPill tone="success">Online</StatusPill>
                    ) : (
                      <StatusPill tone="muted">Offline</StatusPill>
                    )}
                    {node.designated && !node.capable ? (
                      <div className="cell-sub">Designated</div>
                    ) : null}
                  </div>
                </Td>
                <Td label="Last fetch">
                  <LocalTime value={node.last_config_at} />
                </Td>
                <Td>
                  {isOwner ? (
                    <div className="cell-actions">
                      <Button
                        variant={node.designated ? "quiet-danger" : "secondary"}
                        size="sm"
                        disabled={pending}
                        loading={busy === `designate:${node.id}`}
                        aria-label={`${node.designated ? "Release" : "Designate"} ${node.name} as an ingress host`}
                        onClick={() => {
                          if (node.designated) {
                            run(
                              `designate:${node.id}`,
                              () => setIngressDesignationAction(node.id, false),
                              {
                                success: "Ingress host released",
                                description: `${node.name} no longer receives routes.`,
                              },
                            );
                          } else {
                            setDesignating(node);
                          }
                        }}
                      >
                        {node.designated ? "Release" : "Designate"}
                      </Button>
                    </div>
                  ) : null}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      )}
      <ConfirmDialog
        open={designating !== null}
        tone="danger"
        title="Designate a public ingress host?"
        description={
          designating
            ? `${designating.name} will receive every live route, including overlay targets and sign-in allowlists, and serve them to the Internet.`
            : null
        }
        confirmText={designating?.name}
        confirmLabel="Designate host"
        pending={designating !== null && busy === `designate:${designating.id}`}
        onCancel={() => setDesignating(null)}
        onConfirm={() => {
          if (!designating) return;
          const node = designating;
          run(
            `designate:${node.id}`,
            () => setIngressDesignationAction(node.id, true),
            { success: "Ingress host designated", description: `${node.name} now serves live routes.` },
            () => setDesignating(null),
          );
        }}
      />
    </Section>
  );
}
