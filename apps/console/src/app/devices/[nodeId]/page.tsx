import { errorText } from "@/lib/server-errors";
import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { Suspense } from "react";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { Badge, StatusPill } from "@/components/ui/badge";
import { MonoValue } from "@/components/ui/mono-value";
import { Section } from "@/components/ui/section";
import { SkeletonTable } from "@/components/ui/skeleton";
import { PeerLifecycle } from "@/components/peer-lifecycle";
import { PqPeerTable } from "@/components/pq-peer-table";
import {
  CoordRequestError,
  getPeerDetail,
  type PeerDetail,
} from "@/lib/coord-peers";
import { getPqOverview } from "@/lib/coord-pq";
import { listMemberships } from "@/lib/oidc";
import { isOrgRole, roleLabel } from "@/lib/roles";
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
  online: { label: "Online", tone: "success" },
  stale: { label: "Stale heartbeat", tone: "danger" },
  never: { label: "Never seen", tone: "muted" },
} as const;

/** "node.routes_updated" → "Routes updated". */
function auditLabel(action: string): string {
  const words = action.replace(/^node\./u, "").replace(/[._]/gu, " ").trim();
  return words ? words[0].toUpperCase() + words.slice(1) : action;
}

async function TunnelProtection({ ctx, nodeId }: { ctx: ConsoleContext; nodeId: string }) {
  const protection = await getPqOverview(ctx, nodeId).then(
    (overview) => ({ rows: overview.peers, error: null }),
    (error: unknown) => ({
      rows: [],
      error: errorText(error, "Could not load tunnel protection."),
    }),
  );
  return protection.error ? (
    <Alert tone="error" title="Couldn't load tunnel protection">
      {protection.error}
    </Alert>
  ) : (
    <PqPeerTable rows={protection.rows} />
  );
}

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
          errorText(error, "Could not load this device.")
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
          <Link className="back-link" href="/devices">
            ← All devices
          </Link>
          <PageHeader
            eyebrow="Devices"
            title={found ? "Device unavailable" : "Device not found"}
          />
          {found && "error" in found ? (
            <Alert tone="error" title="Couldn't load this device">
              {found.error}
            </Alert>
          ) : (
            <div className="panel">
              <EmptyState
                title="No device with that ID in your networks"
                body="It may have been deleted, or it belongs to a network account you cannot open."
                action={
                  <Link className="button secondary" href="/devices">
                    Back to all devices
                  </Link>
                }
              />
            </div>
          )}
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
        <Link className="back-link" href="/devices">
          ← All devices
        </Link>
        <PageHeader
          eyebrow={ctx.organisationName}
          title={label}
          description={`Technical name ${node.name}. Times use this browser's clock; online and stale are decided by coordinator time.`}
          actions={
            lifecycle === "active" ? (
              <>
                <Link
                  className="button secondary"
                  href={`/devices/${node.id}/terminal?organisation=${ctx.organisationId}`}
                >
                  Open terminal (SSH)
                </Link>
                <Link
                  className="button secondary"
                  href={`/devices/${node.id}/desktop?organisation=${ctx.organisationId}`}
                >
                  Open remote desktop (RDP)
                </Link>
              </>
            ) : undefined
          }
        />

        {lifecycle === "suspended" ? (
          <Alert tone="warning" title="Suspended">
            Suspended {when(detail.lifecycle.suspended_at)}. It is left out of every peer map until
            you resume it.
          </Alert>
        ) : lifecycle !== "active" ? (
          <Alert tone="info" title={lifecycle === "revoked" ? "Revoked" : "Deleted"}>
            This device is {lifecycle}. It can no longer use {ctx.organisationName}.
          </Alert>
        ) : null}

        {detail.version.status === "below_minimum" ? (
          <Alert tone="warning" title="Agent needs an upgrade">
            Agent {detail.version.agent_version} is older than the minimum this coordinator
            supports ({detail.version.minimum_version}). Follow the{" "}
            <a href={UPGRADE_GUIDE_URL}>upgrade guide</a>.
          </Alert>
        ) : null}

        <Section id="identity" title="Identity">
          <dl className="details">
            <div>
              <dt>Node ID</dt>
              <dd>
                <MonoValue value={node.id} copy copyLabel="Copy node ID" />
              </dd>
            </div>
            <div>
              <dt>Owner</dt>
              <dd>
                {owner ? owner.name || owner.email : node.user_id || "Unknown"}
                <div className="cell-sub">
                  Enrolled as {isOrgRole(node.user_role) ? roleLabel(node.user_role) : node.user_role}
                </div>
              </dd>
            </div>
            <div>
              <dt>WireGuard key fingerprint</dt>
              <dd>
                <MonoValue
                  value={detail.public_key_fingerprint}
                  copy
                  copyLabel="Copy key fingerprint"
                />
              </dd>
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
              <dd>
                {node.dns_name ? (
                  <MonoValue value={node.dns_name} copy copyLabel="Copy MagicDNS name" />
                ) : (
                  "Not assigned"
                )}
              </dd>
            </div>
            <div>
              <dt>Addresses</dt>
              <dd className="value-list">
                {node.allowed_ips.length > 0
                  ? node.allowed_ips.map((ip) => (
                      <MonoValue key={ip} value={ip} copy copyLabel={`Copy address ${ip}`} />
                    ))
                  : "None"}
              </dd>
            </div>
            <div>
              <dt>Tags</dt>
              <dd>
                {node.tags.length > 0 ? (
                  <span className="tag-list">
                    {node.tags.map((tag) => (
                      <Badge key={tag}>{tag}</Badge>
                    ))}
                  </span>
                ) : (
                  "None"
                )}
              </dd>
            </div>
            <div>
              <dt>Enrolled</dt>
              <dd>{when(node.created_at)}</dd>
            </div>
          </dl>
        </Section>

        <Section id="health" title="Health and connectivity">
          <dl className="details">
            <div>
              <dt>Last heartbeat</dt>
              <dd>
                <StatusPill tone={heartbeat.tone}>{heartbeat.label}</StatusPill>{" "}
                {when(detail.heartbeat.last_seen_at)}
                <div className="cell-sub">
                  {age(detail.heartbeat.age_seconds)}
                  {` · online means a heartbeat within ${detail.heartbeat.online_window_seconds} seconds`}
                </div>
              </dd>
            </div>
            <div>
              <dt>Transport</dt>
              <dd>
                {transportLabel[detail.transport.state]}
                <div className="cell-sub">
                  {detail.transport.reported_at
                    ? `Reported by the agent ${when(detail.transport.reported_at)} from fresh WireGuard handshakes`
                    : "This agent has not reported a measured path. Older agents and idle tunnels report nothing."}
                </div>
              </dd>
            </div>
            <div>
              <dt>Relay-observed UDP endpoint</dt>
              <dd>
                {detail.transport.relay_endpoint ? (
                  <MonoValue value={detail.transport.relay_endpoint} />
                ) : (
                  "Not observed"
                )}
                {detail.transport.relay_endpoint_updated_at ? (
                  <div className="cell-sub">
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
                  <div className="cell-sub">
                    <StatusPill tone="danger">Expired</StatusPill> Run{" "}
                    <span className="mono">blaktaild reauth</span> with a fresh join key.
                  </div>
                ) : node.expires_soon ? (
                  <div className="cell-sub">Expires within 14 days.</div>
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
                <div className="cell-sub">
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
        </Section>

        <Section
          id="protection"
          title="Tunnel protection per peer"
          description={
            <>
              What this device&apos;s agent reports it negotiated with each peer. Policy is set on{" "}
              <Link href="/tunnel-protection">Tunnel protection</Link> for {ctx.organisationName}.
            </>
          }
        >
          <Suspense fallback={<SkeletonTable rows={3} label="Loading tunnel protection" />}>
            <TunnelProtection ctx={ctx} nodeId={node.id} />
          </Suspense>
        </Section>

        <Section id="routes" title="Routes and policy">
          <dl className="details">
            <div>
              <dt>Advertised routes</dt>
              <dd>
                {node.advertised_routes.length > 0 ? (
                  <MonoValue value={node.advertised_routes.join(", ")} wrap />
                ) : (
                  "None"
                )}
              </dd>
            </div>
            <div>
              <dt>Approved routes</dt>
              <dd>
                {node.approved_routes.length > 0 ? (
                  <MonoValue
                    value={node.approved_routes
                      .map((route) => (route === "0.0.0.0/0" ? "exit node" : route))
                      .join(", ")}
                    wrap
                  />
                ) : (
                  "None"
                )}
              </dd>
            </div>
          </dl>
          <p className="muted">
            Approve routes from the device&apos;s details on <Link href="/devices">Devices</Link>.
            Which peers can reach this device is decided by tags and the{" "}
            <Link href="/acls">access policy</Link> for {ctx.organisationName}.
          </p>
          <nav className="stack" aria-label="Related pages for this device">
            <ul className="link-list">
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
        </Section>

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

        <Section id="audit" title="Recent changes to this device">
          {detail.audit.length === 0 ? (
            <EmptyState
              compact
              headingLevel={3}
              title="No recent changes"
              body={`Nothing was audited for this device in the latest ${ctx.organisationName} audit window.`}
            />
          ) : (
            <ol className="audit-trail">
              {detail.audit.map((event) => (
                <li key={event.id} className="audit-event">
                  <span className="audit-node" aria-hidden="true" />
                  <strong title={event.action}>{auditLabel(event.action)}</strong>
                  <div>
                    {event.actor_email || event.actor_name || event.actor_user_id}
                    {event.actor_role ? ` · ${event.actor_role}` : ""}
                  </div>
                  <div className="cell-sub">
                    <time dateTime={new Date(event.created_at * 1000).toISOString()}>
                      {when(event.created_at)}
                    </time>
                  </div>
                </li>
              ))}
            </ol>
          )}
          <p className="muted">
            The full trail is on the <Link href="/audit">audit log</Link> for the
            organisation selected in the switcher.
          </p>
        </Section>
      </div>
    </ConsoleShell>
  );
}
