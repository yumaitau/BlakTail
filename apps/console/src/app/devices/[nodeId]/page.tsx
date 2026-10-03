import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { PeerLifecycle } from "@/components/peer-lifecycle";
import {
  CoordRequestError,
  getPeerDetail,
  type PeerDetail,
} from "@/lib/coord-peers";
import { listMemberships } from "@/lib/oidc";
import {
  organisationContext,
  requirePersonSessionContext,
  type ConsoleContext,
} from "@/lib/session";

const UPGRADE_GUIDE_URL =
  "https://github.com/jusso-dev/BlakTail/blob/main/docs/upgrades.md";

function when(value: number | null | undefined): string {
  if (!value) return "Never";
  return new Date(value * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function age(seconds: number | null): string {
  if (seconds === null) return "";
  if (seconds < 90) return `${seconds} seconds ago`;
  if (seconds < 7200) return `${Math.round(seconds / 60)} minutes ago`;
  if (seconds < 172_800) return `${Math.round(seconds / 3600)} hours ago`;
  return `${Math.round(seconds / 86_400)} days ago`;
}

const heartbeatLabel = {
  online: { label: "Online", className: "online" },
  stale: { label: "Stale heartbeat", className: "warn" },
  never: { label: "Never seen", className: "offline" },
} as const;

const transportLabel = {
  direct: "Direct UDP",
  relay: "Australian relay",
  mixed: "Mixed (some peers relayed)",
  not_measured: "Not measured",
} as const;

async function findDetail(
  contexts: ConsoleContext[],
  nodeId: string,
): Promise<{ ctx: ConsoleContext; detail: PeerDetail } | { error: string } | null> {
  for (const ctx of contexts) {
    try {
      return { ctx, detail: await getPeerDetail(ctx, nodeId) };
    } catch (error) {
      if (error instanceof CoordRequestError && error.status === 404) continue;
      return {
        error: `${ctx.organisationName}: ${
          error instanceof Error ? error.message : "Could not load this device."
        }`,
      };
    }
  }
  return null;
}

export default async function DeviceDetailPage({
  params,
  searchParams,
}: {
  params: Promise<{ nodeId: string }>;
  searchParams: Promise<{ organisation?: string }>;
}) {
  const person = await requirePersonSessionContext();
  const { nodeId } = await params;
  const { organisation } = await searchParams;
  const candidates = person.organisations
    .filter((row) => !organisation || row.organisationId === organisation)
    .map((row) => organisationContext(person, row.organisationId));
  const found = /^[0-9a-f-]{36}$/i.test(nodeId)
    ? await findDetail(candidates, nodeId)
    : null;

  if (!found || "error" in found) {
    return (
      <ConsoleShell ctx={person} current="/devices">
        <div className="stack">
          <PageHeader eyebrow="Devices" title="Device not found" />
          <div className="panel">
            {found && "error" in found ? (
              <p className="error" role="alert">
                {found.error}
              </p>
            ) : (
              <EmptyState
                title="No device with that id in your networks"
                body="It may have been deleted, or it belongs to a network account you cannot open."
                action={<Link href="/devices">Back to all devices</Link>}
              />
            )}
          </div>
        </div>
      </ConsoleShell>
    );
  }

  const { ctx, detail } = found;
  const { node } = detail;
  const label = node.display_name || node.name;
  const owner = (await listMemberships(ctx.organisationId).catch(() => [])).find(
    (row) => row.userId === node.user_id,
  );
  const heartbeat = heartbeatLabel[detail.heartbeat.state];
  const lifecycle = detail.lifecycle.state;

  return (
    <ConsoleShell ctx={person} current="/devices">
      <div className="stack">
        <p>
          <Link href="/devices">← All devices</Link>
        </p>
        <PageHeader
          eyebrow={ctx.organisationName}
          title={label}
          description={`Technical name ${node.name}. Times use this browser's clock; online and stale are decided by coordinator time.`}
        />

        {lifecycle === "active" ? (
          <p className="row">
            <Link href={`/devices/${node.id}/terminal?organisation=${ctx.organisationId}`}>Open browser terminal (SSH)</Link>
            <Link href={`/devices/${node.id}/desktop?organisation=${ctx.organisationId}`}>Open remote desktop (RDP)</Link>
          </p>
        ) : null}

        {lifecycle !== "active" ? (
          <p className={lifecycle === "suspended" ? "error" : "muted"} role="status">
            {lifecycle === "suspended"
              ? `Suspended ${when(detail.lifecycle.suspended_at)}. It is excluded from every peer map until resumed.`
              : `This device is ${lifecycle}.`}
          </p>
        ) : null}

        {detail.version.status === "below_minimum" ? (
          <p className="error" role="status">
            Agent {detail.version.agent_version} is older than the minimum this
            coordinator supports ({detail.version.minimum_version}). Follow the{" "}
            <a href={UPGRADE_GUIDE_URL}>upgrade guide</a>.
          </p>
        ) : null}

        <section className="panel stack" aria-labelledby="identity-title">
          <h2 id="identity-title">Identity</h2>
          <dl className="details">
            <div>
              <dt>Node id</dt>
              <dd className="mono">{node.id}</dd>
            </div>
            <div>
              <dt>Owner</dt>
              <dd>
                {owner ? owner.name || owner.email : node.user_id || "Unknown"}
                <div className="muted">Enrolled as {node.user_role}</div>
              </dd>
            </div>
            <div>
              <dt>WireGuard key fingerprint</dt>
              <dd className="mono">{detail.public_key_fingerprint}</dd>
            </div>
            <div>
              <dt>Friendly name</dt>
              <dd>{node.display_name || "Not set"}</dd>
            </div>
            <div>
              <dt>Technical name</dt>
              <dd className="mono">{node.name}</dd>
            </div>
            <div>
              <dt>MagicDNS</dt>
              <dd className="mono">{node.dns_name || "—"}</dd>
            </div>
            <div>
              <dt>Addresses</dt>
              <dd className="mono">{node.allowed_ips.join(", ") || "—"}</dd>
            </div>
            <div>
              <dt>Tags</dt>
              <dd>
                {node.tags.length > 0
                  ? node.tags.map((tag) => (
                      <span key={tag} className="badge">
                        {tag}
                      </span>
                    ))
                  : "None"}
              </dd>
            </div>
            <div>
              <dt>Enrolled</dt>
              <dd>{when(node.created_at)}</dd>
            </div>
          </dl>
        </section>

        <section className="panel stack" aria-labelledby="health-title">
          <h2 id="health-title">Health and connectivity</h2>
          <dl className="details">
            <div>
              <dt>Last heartbeat</dt>
              <dd>
                <span className={`badge ${heartbeat.className}`}>{heartbeat.label}</span>{" "}
                {when(detail.heartbeat.last_seen_at)}
                <div className="muted">
                  {age(detail.heartbeat.age_seconds)}
                  {` · online means a heartbeat within ${detail.heartbeat.online_window_seconds} seconds`}
                </div>
              </dd>
            </div>
            <div>
              <dt>Transport</dt>
              <dd>
                {transportLabel[detail.transport.state]}
                <div className="muted">
                  {detail.transport.reported_at
                    ? `Reported by the agent ${when(detail.transport.reported_at)} from fresh WireGuard handshakes`
                    : "This agent has not reported a measured path. Older agents and idle tunnels report nothing."}
                </div>
              </dd>
            </div>
            <div>
              <dt>Relay-observed UDP endpoint</dt>
              <dd>
                <span className="mono">{detail.transport.relay_endpoint || "—"}</span>
                {detail.transport.relay_endpoint_updated_at ? (
                  <div className="muted">
                    Updated {when(detail.transport.relay_endpoint_updated_at)}
                  </div>
                ) : null}
              </dd>
            </div>
            <div>
              <dt>Credential expires</dt>
              <dd>
                {when(node.credential_expires_at)}
                {node.expired ? (
                  <div className="error">Expired: run blaktaild reauth with a fresh join key.</div>
                ) : node.expires_soon ? (
                  <div className="muted">Expires within 14 days.</div>
                ) : null}
              </dd>
            </div>
            <div>
              <dt>Machine</dt>
              <dd>
                {node.os || "Unknown OS"}
                {node.os_version ? ` ${node.os_version}` : ""}
                {node.hostname ? ` · ${node.hostname}` : ""}
              </dd>
            </div>
            <div>
              <dt>Agent version</dt>
              <dd>
                <span className="mono">{detail.version.agent_version || "Not reported"}</span>
                <div className="muted">
                  {detail.version.status === "below_minimum"
                    ? "Upgrade required."
                    : detail.version.status === "unknown"
                      ? "Version could not be compared."
                      : "Supported."}{" "}
                  Minimum {detail.version.minimum_version}.{" "}
                  <a href={UPGRADE_GUIDE_URL}>Upgrade guide</a>
                </div>
              </dd>
            </div>
          </dl>
        </section>

        <section className="panel stack" aria-labelledby="routes-title">
          <h2 id="routes-title">Routes and policy</h2>
          <dl className="details">
            <div>
              <dt>Advertised routes</dt>
              <dd className="mono">{node.advertised_routes.join(", ") || "None"}</dd>
            </div>
            <div>
              <dt>Approved routes</dt>
              <dd className="mono">
                {node.approved_routes
                  .map((route) => (route === "0.0.0.0/0" ? "exit node" : route))
                  .join(", ") || "None"}
              </dd>
            </div>
          </dl>
          <p className="muted">
            Approve routes from the device row on <Link href="/devices">Devices</Link>.
            Which peers can reach this device is decided by tags and the{" "}
            <Link href="/acls">access policy</Link> for {ctx.organisationName}.
          </p>
          <nav aria-label="Related pages for this device">
            <ul className="audit-details">
              <li>
                <Link href={`/topology?node=${node.id}&organisation=${ctx.organisationId}`}>
                  Who this device can reach, and who can reach it
                </Link>{" "}
                <span className="muted">(effective paths in {ctx.organisationName})</span>
              </li>
              <li>
                <Link href="/networks">Network resources and routing peers</Link>
              </li>
              <li>
                <Link href="/dns">DNS</Link>{" "}
                <span className="muted">(MagicDNS name {node.dns_name || "not assigned"})</span>
              </li>
              <li>
                <Link href="/changes">Stage policy, route and DNS changes together</Link>
              </li>
            </ul>
            <p className="muted">
              Networks, DNS, access policy and change drafts open for the organisation selected in
              the switcher; make sure it is {ctx.organisationName}.
            </p>
          </nav>
        </section>

        <PeerLifecycle
          nodeId={node.id}
          label={label}
          organisationId={ctx.organisationId}
          organisationName={ctx.organisationName}
          role={ctx.role}
          state={lifecycle}
          approvedRoutes={node.approved_routes}
          tags={node.tags}
        />

        <section className="panel stack" aria-labelledby="audit-title">
          <h2 id="audit-title">Recent changes to this device</h2>
          {detail.audit.length === 0 ? (
            <p className="muted">
              No audited changes in the latest {ctx.organisationName} audit window.
            </p>
          ) : (
            <ol className="audit-trail">
              {detail.audit.map((event) => (
                <li key={event.id} className="audit-event">
                  <span className="audit-node" aria-hidden="true" />
                  <strong>{event.action}</strong>
                  <div>
                    {event.actor_email || event.actor_name || event.actor_user_id}
                    {event.actor_role ? ` · ${event.actor_role}` : ""}
                  </div>
                  <div className="muted mono">{new Date(event.created_at * 1000).toISOString()}</div>
                </li>
              ))}
            </ol>
          )}
          <p className="muted">
            The full trail is on the <Link href="/audit">audit log</Link> for the
            organisation selected in the switcher.
          </p>
        </section>
      </div>
    </ConsoleShell>
  );
}
