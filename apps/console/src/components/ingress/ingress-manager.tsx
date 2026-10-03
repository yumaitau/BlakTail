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
import type {
  IngressWorkspace,
  PublicRoute,
  RouteStatus,
} from "@/lib/coord-ingress";

type Option = { id: string; label: string };
type Result = { ok: true } | { ok: false; error: string };

const STATUS: Record<RouteStatus, { label: string; tone: string; detail: string }> = {
  active: { label: "Live on the Internet", tone: "public", detail: "An online ingress serves this route." },
  organisation_disabled: {
    label: "Organisation off",
    tone: "offline",
    detail: "Public ingress is turned off for this organisation, so nothing is served.",
  },
  emergency_disabled: {
    label: "Emergency disabled",
    tone: "warn",
    detail: "Withdrawn from every ingress. An owner must re-enable it.",
  },
  disabled: { label: "Disabled", tone: "offline", detail: "Not served." },
  target_unavailable: {
    label: "Target unavailable",
    tone: "warn",
    detail: "The target device or service is revoked, suspended, expired or disabled.",
  },
  target_unsupported: {
    label: "Target unsupported",
    tone: "warn",
    detail: "The ingress reaches targets over plain HTTP inside the overlay; the service must use HTTP.",
  },
  target_is_ingress: {
    label: "Target is the ingress",
    tone: "warn",
    detail: "Choose a different device from the ingress host.",
  },
  blocked_by_policy: {
    label: "Blocked by policy",
    tone: "warn",
    detail: "Access policy does not let the ingress device reach this target port, so it is not served. A public URL never widens policy.",
  },
  ingress_offline: {
    label: "Ingress offline",
    tone: "pending",
    detail: "Allowed, but no ingress has fetched its configuration recently.",
  },
  ingress_not_capable: {
    label: "Ingress not enabled",
    tone: "pending",
    detail: "Run blaktaild up --public-ingress on the ingress host.",
  },
  ingress_not_designated: {
    label: "Ingress not designated",
    tone: "pending",
    detail: "An owner must designate this device as an ingress host before it receives routes.",
  },
  no_ingress_node: {
    label: "No ingress host",
    tone: "pending",
    detail: "Enrol an onshore host with blaktaild up --public-ingress and run blaktail-ingress there.",
  },
};

function when(seconds: number | null): string {
  if (!seconds) return "never";
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function days(seconds: number): number {
  return Math.floor((seconds * 1000 - Date.now()) / 86_400_000);
}

export function IngressManager({
  workspace,
  devices,
  services,
  organisationName,
  roleLabel,
  ownerReason,
  canEmergencyDisable,
}: {
  workspace: IngressWorkspace;
  devices: Option[];
  services: Option[];
  organisationName: string;
  roleLabel: string;
  ownerReason: string | null;
  canEmergencyDisable: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const isOwner = ownerReason === null;

  function run(action: () => Promise<Result>, after?: () => void) {
    setError(null);
    startTransition(async () => {
      const result = await action();
      if (!result.ok) {
        setError(result.error);
        return;
      }
      after?.();
      router.refresh();
    });
  }

  return (
    <div className="stack">
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      <SettingsPanel
        workspace={workspace}
        organisationName={organisationName}
        roleLabel={roleLabel}
        isOwner={isOwner}
        ownerReason={ownerReason}
        pending={pending}
        run={run}
      />
      <div className="panel stack public-panel" id="routes">
        <div>
          <h2>
            Public routes <span className="badge public">PUBLIC</span>
          </h2>
          <p className="muted">
            Each route answers one public hostname and forwards only to its one published target
            over the overlay. The ingress drops a route within{" "}
            {workspace.stale_after_secs} seconds of losing contact with the coordinator, and an
            emergency disable reaches it on its next poll.
          </p>
          {!isOwner && !canEmergencyDisable ? (
            <p className="muted">
              Read only. {ownerReason} Owners, admins and network admins can emergency-disable a
              route.
            </p>
          ) : null}
        </div>
        {workspace.routes.length === 0 ? (
          <p className="muted">No public routes. Nothing from this organisation is on the Internet through BlakTail.</p>
        ) : (
          <ul className="stack public-routes">
            {workspace.routes.map((route) => (
              <RouteCard
                key={route.id}
                route={route}
                isOwner={isOwner}
                canEmergencyDisable={canEmergencyDisable}
                pending={pending}
                run={run}
              />
            ))}
          </ul>
        )}
      </div>
      {isOwner ? (
        <CreateRoute
          enabled={workspace.settings.enabled}
          devices={devices}
          services={services}
          organisationName={organisationName}
          roleLabel={roleLabel}
          pending={pending}
          run={run}
        />
      ) : null}
      <IngressHosts
        workspace={workspace}
        organisationName={organisationName}
        roleLabel={roleLabel}
        ownerReason={ownerReason}
        pending={pending}
        run={run}
      />
    </div>
  );
}

function SettingsPanel({
  workspace,
  organisationName,
  roleLabel,
  isOwner,
  ownerReason,
  pending,
  run,
}: {
  workspace: IngressWorkspace;
  organisationName: string;
  roleLabel: string;
  isOwner: boolean;
  ownerReason: string | null;
  pending: boolean;
  run: (action: () => Promise<Result>, after?: () => void) => void;
}) {
  const [confirm, setConfirm] = useState("");
  const [contact, setContact] = useState(workspace.settings.abuse_contact);
  const { enabled } = workspace.settings;
  return (
    <div className={`panel stack${enabled ? " public-panel" : ""}`} id="settings">
      <div>
        <h2>Organisation setting</h2>
        <p>
          Public ingress is{" "}
          {enabled ? (
            <span className="badge public">ON</span>
          ) : (
            <span className="badge offline">Off</span>
          )}{" "}
          for <span className="badge network">{organisationName}</span>.
          {workspace.settings.abuse_contact
            ? ` Abuse contact: ${workspace.settings.abuse_contact}.`
            : ""}
        </p>
        <p className="muted">
          Your organisation runs the ingress host and chooses its DNS, certificate authority and
          monitoring. BlakTail does not operate a shared ingress and cannot vouch for where those
          providers keep data.
        </p>
      </div>
      {isOwner ? (
        enabled ? (
          <div className="row">
            <button
              type="button"
              className="quiet-danger"
              disabled={pending}
              onClick={() => {
                const form = new FormData();
                form.set("enabled", "false");
                form.set("abuseContact", contact);
                run(() => setIngressEnabledAction(form));
              }}
            >
              Turn off public ingress
            </button>
            <span className="muted">Withdraws every route from every ingress.</span>
          </div>
        ) : (
          <form
            className="stack"
            onSubmit={(event) => {
              event.preventDefault();
              const form = new FormData(event.currentTarget);
              form.set("enabled", "true");
              run(() => setIngressEnabledAction(form), () => setConfirm(""));
            }}
          >
            <p className="muted">
              Turning this on as {roleLabel} lets owners publish routes. It does not publish
              anything by itself.
            </p>
            <div className="dns-grid">
              <label>
                Abuse contact (email or https:// URL)
                <input
                  name="abuseContact"
                  required
                  maxLength={200}
                  value={contact}
                  onChange={(event) => setContact(event.target.value)}
                  disabled={pending}
                />
              </label>
              <label>
                Type PUBLIC to confirm
                <input
                  name="confirm"
                  required
                  autoComplete="off"
                  value={confirm}
                  onChange={(event) => setConfirm(event.target.value)}
                  disabled={pending}
                />
              </label>
            </div>
            <div className="row">
              <button
                type="submit"
                className="danger"
                disabled={pending || confirm !== "PUBLIC" || contact.trim() === ""}
              >
                {pending ? "Working…" : "Allow public ingress"}
              </button>
            </div>
          </form>
        )
      ) : (
        <p className="muted">{ownerReason}</p>
      )}
    </div>
  );
}

function RouteCard({
  route,
  isOwner,
  canEmergencyDisable,
  pending,
  run,
}: {
  route: PublicRoute;
  isOwner: boolean;
  canEmergencyDisable: boolean;
  pending: boolean;
  run: (action: () => Promise<Result>, after?: () => void) => void;
}) {
  const status = STATUS[route.status] ?? STATUS.disabled;
  const [confirm, setConfirm] = useState("");
  const live = route.enabled && route.emergency_disabled_at === null;
  const confirmId = `confirm-${route.id}`;
  return (
    <li className="public-route stack">
      <div className="row public-route-head">
        <span className="badge public">PUBLIC</span>
        <span className="mono public-fqdn">https://{route.fqdn}</span>
        <span className={`badge ${status.tone}`}>{status.label}</span>
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
          <dd>{route.tls_mode === "acme_http01" ? "ACME HTTP-01 on the ingress" : "Operator files on the ingress"}</dd>
        </div>
        <div>
          <dt>Limits</dt>
          <dd>
            {route.limits.rate_limit_per_minute}/min per client,{" "}
            {Math.round(route.limits.max_body_bytes / 1024 / 1024)} MiB bodies,{" "}
            {route.limits.max_connections} connections, logs kept {route.limits.log_retention_days}{" "}
            days
          </dd>
        </div>
      </dl>
      {route.ingress.length > 0 ? (
        <div className="table-wrap">
          <table className="table">
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
                    <td>{ingress.node_name}</td>
                    <td>
                      <span className={`badge ${state.tone}`}>{state.label}</span>
                    </td>
                    <td>
                      {ingress.certificate_not_after ? (
                        <span className={days(ingress.certificate_not_after) < 14 ? "error" : undefined}>
                          Expires {when(ingress.certificate_not_after)} ({days(ingress.certificate_not_after)} days)
                        </span>
                      ) : (
                        <span className="muted">Not reported</span>
                      )}
                      {ingress.last_error ? <div className="error">{ingress.last_error}</div> : null}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      ) : null}
      {route.emergency_disabled_at ? (
        <p className="error">
          Emergency disabled {when(route.emergency_disabled_at)}
          {route.emergency_disabled_by ? ` by ${route.emergency_disabled_by}` : ""}
          {route.emergency_reason ? `: ${route.emergency_reason}` : "."}
        </p>
      ) : null}
      {canEmergencyDisable || isOwner ? (
        <div className="row">
          {canEmergencyDisable && live ? (
            <button
              type="button"
              className="danger"
              disabled={pending}
              onClick={() => {
                const reason = window.prompt(
                  `Emergency disable ${route.fqdn}? It is withdrawn from every ingress on its next poll. Reason (recorded in the audit log):`,
                  "",
                );
                if (reason !== null) {
                  run(() => emergencyDisableAction(route.id, reason));
                }
              }}
            >
              Emergency disable
            </button>
          ) : null}
          {isOwner && live ? (
            <button
              type="button"
              className="secondary"
              disabled={pending}
              onClick={() => run(() => setRouteEnabledAction(route.id, route.revision, false, ""))}
            >
              Disable
            </button>
          ) : null}
          {isOwner && !live ? (
            <>
              <label htmlFor={confirmId} className="visually-hidden">
                Type {route.fqdn} to re-enable
              </label>
              <input
                id={confirmId}
                placeholder={`Type ${route.fqdn} to re-enable`}
                autoComplete="off"
                value={confirm}
                onChange={(event) => setConfirm(event.target.value)}
                disabled={pending}
              />
              <button
                type="button"
                className="danger"
                disabled={pending || confirm.trim().toLowerCase() !== route.fqdn}
                onClick={() =>
                  run(
                    () => setRouteEnabledAction(route.id, route.revision, true, confirm),
                    () => setConfirm(""),
                  )
                }
              >
                Re-enable publicly
              </button>
            </>
          ) : null}
          {isOwner ? (
            <button
              type="button"
              className="quiet-danger"
              disabled={pending}
              onClick={() => {
                if (window.confirm(`Delete the public route for ${route.fqdn}?`)) {
                  run(() => deleteRouteAction(route.id));
                }
              }}
            >
              Delete
            </button>
          ) : null}
        </div>
      ) : null}
    </li>
  );
}

function CreateRoute({
  enabled,
  devices,
  services,
  organisationName,
  roleLabel,
  pending,
  run,
}: {
  enabled: boolean;
  devices: Option[];
  services: Option[];
  organisationName: string;
  roleLabel: string;
  pending: boolean;
  run: (action: () => Promise<Result>, after?: () => void) => void;
}) {
  const formRef = useRef<HTMLFormElement>(null);
  const [fqdn, setFqdn] = useState("");
  const [confirm, setConfirm] = useState("");
  const [target, setTarget] = useState(
    services[0] ? `service:${services[0].id}` : devices[0] ? `node:${devices[0].id}` : "",
  );
  const [auth, setAuth] = useState("none");
  const disabled = pending || !enabled;
  const normalised = fqdn.trim().toLowerCase().replace(/\.$/, "");
  const confirmed = normalised !== "" && confirm.trim().toLowerCase().replace(/\.$/, "") === normalised;
  return (
    <div className="panel stack public-panel" id="create">
      <div>
        <h2>
          Publish a route <span className="badge public">PUBLIC</span>
        </h2>
        <p className="muted">
          Publishing in <span className="badge network">{organisationName}</span> as {roleLabel}.
          Point the hostname&apos;s DNS at your ingress host and place its certificate there (or
          choose ACME). Access policy must also let the ingress device reach the target.
        </p>
        {!enabled ? <p className="muted">Turn on public ingress for the organisation first.</p> : null}
      </div>
      <form
        ref={formRef}
        className="stack"
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          run(
            () => createRouteAction(form),
            () => {
              formRef.current?.reset();
              setFqdn("");
              setConfirm("");
            },
          );
        }}
      >
        <div className="dns-grid">
          <label>
            Public hostname
            <input
              name="fqdn"
              required
              maxLength={253}
              placeholder="bookings.example.org.au"
              value={fqdn}
              onChange={(event) => setFqdn(event.target.value)}
              disabled={disabled}
            />
          </label>
          <label>
            Target
            <select
              name="target"
              required
              value={target}
              onChange={(event) => setTarget(event.target.value)}
              disabled={disabled || (devices.length === 0 && services.length === 0)}
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
          </label>
          {target.startsWith("node:") ? (
            <label>
              Target HTTP port on the device
              <input name="port" type="number" min={1} max={65535} required defaultValue={8080} disabled={disabled} />
            </label>
          ) : null}
          <label>
            Certificate
            <select name="tlsMode" defaultValue="operator_files" disabled={disabled}>
              <option value="operator_files">Operator files on the ingress host</option>
              <option value="acme_http01">ACME HTTP-01 from the ingress host</option>
            </select>
          </label>
          <label>
            Sign-in
            <select name="authMode" value={auth} onChange={(event) => setAuth(event.target.value)} disabled={disabled}>
              <option value="none">None: anyone on the Internet</option>
              <option value="oidc">Organisation sign-in (OIDC)</option>
            </select>
          </label>
          {auth === "oidc" ? (
            <label>
              Allowed email domains (optional)
              <input name="allowedDomains" placeholder="example.org.au" disabled={disabled} />
            </label>
          ) : null}
          <label>
            Allowed client networks (optional, CIDR)
            <input name="allowedSources" placeholder="203.0.113.0/24" disabled={disabled} />
          </label>
          <label>
            Requests per minute per client
            <input name="rate" type="number" min={1} max={60000} defaultValue={600} disabled={disabled} />
          </label>
          <label>
            Largest request body (MiB)
            <input name="maxBodyMiB" type="number" min={0} max={100} defaultValue={10} disabled={disabled} />
          </label>
          <label>
            Concurrent connections
            <input name="maxConnections" type="number" min={1} max={4096} defaultValue={256} disabled={disabled} />
          </label>
          <label>
            Keep access logs (days)
            <input name="retention" type="number" min={1} max={365} defaultValue={30} disabled={disabled} />
          </label>
        </div>
        <label>
          Type the hostname again to confirm it will be reachable from the Internet
          <input
            name="confirmFqdn"
            required
            autoComplete="off"
            value={confirm}
            onChange={(event) => setConfirm(event.target.value)}
            disabled={disabled}
          />
        </label>
        <div className="row">
          <button type="submit" className="danger" disabled={disabled || !confirmed || target === ""}>
            {pending ? "Working…" : "Publish to the Internet"}
          </button>
        </div>
      </form>
    </div>
  );
}

function IngressHosts({
  workspace,
  organisationName,
  roleLabel,
  ownerReason,
  pending,
  run,
}: {
  workspace: IngressWorkspace;
  organisationName: string;
  roleLabel: string;
  ownerReason: string | null;
  pending: boolean;
  run: (action: () => Promise<Result>) => void;
}) {
  return (
    <div className="panel stack" id="hosts">
      <div>
        <h2>Ingress hosts</h2>
        <p className="muted">
          Devices running <span className="mono">blaktaild up --public-ingress</span>. Reporting the
          capability is not enough: an owner must designate a device before it receives any route,
          because it learns every route&apos;s overlay target and sign-in allowlist. Each designated
          host serves every live route; online means it fetched configuration in the last 90
          seconds.
        </p>
        <p className="muted">
          {ownerReason
            ? `Read only. ${ownerReason}`
            : `Designations for ${organisationName} as ${roleLabel} are audited.`}
        </p>
      </div>
      {workspace.ingress_nodes.length === 0 ? (
        <p className="muted">No ingress host has been set up.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
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
                  <td>{node.name}</td>
                  <td>
                    {!node.capable ? (
                      <span className="badge pending">Capability off</span>
                    ) : !node.designated ? (
                      <span className="badge pending">Not designated</span>
                    ) : node.online ? (
                      <span className="badge online">Online</span>
                    ) : (
                      <span className="badge offline">Offline</span>
                    )}
                  </td>
                  <td>{when(node.last_config_at)}</td>
                  <td>
                    <button
                      type="button"
                      className={node.designated ? "quiet-danger" : "secondary"}
                      disabled={pending || ownerReason !== null}
                      title={ownerReason ?? undefined}
                      aria-label={`${node.designated ? "Release" : "Designate"} ${node.name} as an ingress host`}
                      onClick={() => {
                        if (
                          node.designated ||
                          window.confirm(
                            `Designate ${node.name} as a public ingress host? It will receive every live route, including overlay targets and sign-in allowlists.`,
                          )
                        ) {
                          run(() => setIngressDesignationAction(node.id, !node.designated));
                        }
                      }}
                    >
                      {node.designated ? "Release" : "Designate"}
                    </button>
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
