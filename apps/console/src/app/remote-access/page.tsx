import { errorText } from "@/lib/server-errors";
import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import {
  AcceptHostKeyButton,
  GatewaySettingsForm,
  RevokeSessionButton,
} from "@/components/remote-access-manager";
import { listNodes, type CoordNode } from "@/lib/coord";
import {
  getRemoteSettings,
  listHostKeys,
  listRemoteSessions,
  type HostKey,
  type RemoteSession,
  type RemoteSettings,
} from "@/lib/coord-remote";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

function when(seconds: number | null): string {
  if (!seconds) return "—";
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 / 1024).toFixed(1)} MiB`;
}

const GATEWAY_STATE: Record<RemoteSettings["gateway_state"], { label: string; badge: string }> = {
  not_configured: { label: "Not set up", badge: "badge" },
  online: { label: "Online", badge: "badge online" },
  offline: { label: "Offline", badge: "badge offline" },
  suspended: { label: "Suspended", badge: "badge revoked" },
  credential_expired: { label: "Credential expired", badge: "badge warn" },
  removed: { label: "Removed", badge: "badge revoked" },
};

const SESSION_BADGE: Record<RemoteSession["status"], string> = {
  issued: "badge pending",
  active: "badge online",
  ended: "badge",
  expired: "badge",
  revoked: "badge revoked",
};

export default async function RemoteAccessPage() {
  const ctx = await requireConsoleContext();
  const sessionsDenied = permissionReason(ctx.role, "use_remote_sessions");
  let settings: RemoteSettings | null = null;
  let hostKeys: HostKey[] = [];
  let nodes: CoordNode[] = [];
  let sessions: RemoteSession[] = [];
  let error: string | null = null;
  try {
    [settings, hostKeys, nodes, sessions] = await Promise.all([
      getRemoteSettings(ctx),
      listHostKeys(ctx),
      listNodes(ctx),
      sessionsDenied ? Promise.resolve([]) : listRemoteSessions(ctx),
    ]);
  } catch (err) {
    error = errorText(err, "Could not load remote access.");
  }
  const names = new Map(nodes.map((node) => [node.id, node.display_name || node.name]));
  const active = nodes.filter((node) => !node.revoked && !node.deleted);
  const pending = hostKeys.filter((key) => key.pending_fingerprint);

  return (
    <ConsoleShell ctx={ctx} current="/remote-access">
      <div className="stack">
        <PageHeader
          eyebrow="Remote"
          title="Remote access"
          description="Browser SSH (and RDP where guacd is deployed) through this organisation's onshore gateway. The gateway is an ordinary BlakTail device, so access policy and SSH rules decide what it can reach."
        />
        <p className="muted">
          {ctx.organisationName} · {roleLabel(ctx.role)}
        </p>
        {error ? (
          <div className="panel stack">
            <p className="error" role="alert">
              {error}
            </p>
            <p className="muted">Check that the coordinator is running, then reload.</p>
          </div>
        ) : null}

        {settings ? (
          <section className="panel stack" aria-labelledby="gateway-title">
            <h2 id="gateway-title">Gateway</h2>
            <dl className="details">
              <div>
                <dt>State</dt>
                <dd>
                  <span className={GATEWAY_STATE[settings.gateway_state].badge}>
                    {GATEWAY_STATE[settings.gateway_state].label}
                  </span>
                  {settings.gateway_name ? ` ${settings.gateway_name}` : null}
                </dd>
              </div>
              <div>
                <dt>Browser address</dt>
                <dd className="mono">{settings.gateway_url || "—"}</dd>
              </div>
              <div>
                <dt>Limits</dt>
                <dd>
                  Ticket valid {settings.ticket_ttl_seconds} seconds, single use · session at most{" "}
                  {settings.max_session_seconds / 60} minutes · idle timeout{" "}
                  {settings.idle_timeout_seconds / 60} minutes
                </dd>
              </div>
              <div>
                <dt>Organisation SSH user CA</dt>
                <dd className="mono">{settings.ca_public_key || "Created when an owner first saves a gateway"}</dd>
              </div>
            </dl>
            <GatewaySettingsForm
              devices={active.map((node) => ({ id: node.id, label: node.display_name || node.name }))}
              gatewayNodeId={settings.gateway_node_id}
              gatewayUrl={settings.gateway_url}
              disabledReason={permissionReason(ctx.role, "manage_security")}
            />
            <p className="muted">
              Devices trust the CA only for connections from the gateway, and only when their
              operator opted in: <span className="mono">BLAKTAIL_SSHD_DROPIN</span> and{" "}
              <span className="mono">BLAKTAIL_SSH_USER_CA</span> on a Linux agent. See{" "}
              <Link href="https://github.com/jusso-dev/BlakTail/blob/main/docs/remote-access.md">
                docs/remote-access.md
              </Link>
              .
            </p>
          </section>
        ) : null}

        <section className="panel stack" aria-labelledby="hostkeys-title">
          <h2 id="hostkeys-title">SSH host keys</h2>
          <p className="muted">
            Each device&apos;s agent reports its Ed25519 host key. The gateway refuses any other
            key. A changed key blocks sessions until someone who can manage devices checks it on
            the device and accepts it.
          </p>
          {hostKeys.length === 0 ? (
            <EmptyState
              title="No host keys reported yet"
              body="Agents report /etc/ssh/ssh_host_ed25519_key.pub after their next sync."
            />
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Device</th>
                    <th scope="col">Pinned key</th>
                    <th scope="col">Pending change</th>
                  </tr>
                </thead>
                <tbody>
                  {hostKeys.map((key) => (
                    <tr key={key.node_id}>
                      <td>
                        <Link href={`/devices/${key.node_id}`}>{names.get(key.node_id) ?? key.node_id}</Link>
                      </td>
                      <td className="mono">{key.fingerprint}</td>
                      <td>
                        {key.pending_fingerprint ? (
                          <div className="stack">
                            <span className="mono">{key.pending_fingerprint}</span>
                            <span className="muted">Reported {when(key.pending_reported_at)}</span>
                            <AcceptHostKeyButton
                              nodeId={key.node_id}
                              fingerprint={key.pending_fingerprint}
                              deviceName={names.get(key.node_id) ?? key.node_id}
                              disabledReason={permissionReason(ctx.role, "manage_peers")}
                            />
                          </div>
                        ) : (
                          "None"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {pending.length > 0 ? (
            <p className="error" role="status">
              {pending.length} device{pending.length === 1 ? "" : "s"} reported a new host key.
              Sessions to {pending.length === 1 ? "it" : "them"} are blocked until accepted.
            </p>
          ) : null}
        </section>

        <section className="panel stack" aria-labelledby="sessions-title">
          <h2 id="sessions-title">Recent sessions</h2>
          {sessionsDenied ? (
            <p role="note">{sessionsDenied}</p>
          ) : sessions.length === 0 ? (
            <EmptyState
              title="No sessions yet"
              body="Open a device and choose Open terminal to start one."
              action={<Link href="/devices">Devices</Link>}
            />
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Status</th>
                    <th scope="col">Person</th>
                    <th scope="col">Device and account</th>
                    <th scope="col">Reason</th>
                    <th scope="col">Started</th>
                    <th scope="col">Ended</th>
                    <th scope="col">Bytes in / out</th>
                    <th scope="col">
                      <span className="visually-hidden">Actions</span>
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {sessions.map((session) => (
                    <tr key={session.id}>
                      <td>
                        <span className={SESSION_BADGE[session.status]}>{session.status}</span>{" "}
                        <span className="muted">{session.kind.toUpperCase()}</span>
                      </td>
                      <td>{session.user_name || session.user_id}</td>
                      <td>
                        <span className="mono">{session.os_user}</span>@
                        {names.get(session.target_node_id) ?? session.target_node_id}
                      </td>
                      <td>{session.reason}</td>
                      <td>{when(session.redeemed_at ?? session.created_at)}</td>
                      <td>
                        {when(session.ended_at)}
                        {session.end_reason ? <div className="muted">{session.end_reason}</div> : null}
                      </td>
                      <td>
                        {bytes(session.bytes_to_target)} / {bytes(session.bytes_from_target)}
                      </td>
                      <td>
                        {(session.status === "active" || session.status === "issued") &&
                        can(ctx.role, "use_remote_sessions") ? (
                          <RevokeSessionButton sessionId={session.id} />
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </ConsoleShell>
  );
}
