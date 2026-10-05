import { Suspense } from "react";
import { errorText } from "@/lib/server-errors";
import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import {
  Alert,
  Card,
  EmptyState,
  PageHeader,
  Section,
  SkeletonTable,
  StatusPill,
  Table,
  Td,
  type BadgeTone,
} from "@/components/ui";
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
import { formatDateTime } from "@/lib/format-time";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

function bytes(value: number): string {
  if (value < 1024) return `${value} B`;
  if (value < 1024 * 1024) return `${(value / 1024).toFixed(1)} KiB`;
  return `${(value / 1024 / 1024).toFixed(1)} MiB`;
}

const GATEWAY_STATE: Record<RemoteSettings["gateway_state"], { label: string; tone: BadgeTone }> = {
  not_configured: { label: "Not set up", tone: "muted" },
  online: { label: "Online", tone: "success" },
  offline: { label: "Offline", tone: "muted" },
  suspended: { label: "Suspended", tone: "danger" },
  credential_expired: { label: "Credential expired", tone: "warning" },
  removed: { label: "Removed", tone: "danger" },
};

const SESSION_STATE: Record<RemoteSession["status"], { label: string; tone: BadgeTone }> = {
  issued: { label: "Starting", tone: "warning" },
  active: { label: "Active", tone: "success" },
  ended: { label: "Ended", tone: "muted" },
  expired: { label: "Expired", tone: "muted" },
  revoked: { label: "Revoked", tone: "danger" },
};

export default async function RemoteAccessPage() {
  const ctx = await requireConsoleContext();
  return (
    <ConsoleShell ctx={ctx} current="/remote-access">
      <div className="stack">
        <PageHeader
          eyebrow="Remote"
          title="Remote access"
          description="Browser SSH (and RDP where guacd is deployed) through this organisation's onshore gateway. The gateway is an ordinary BlakTail device, so access policy and SSH rules decide what it can reach."
        />
        <p className="page-context">
          {ctx.organisationName} · {roleLabel(ctx.role)}
        </p>
        <Suspense
          fallback={
            <Card>
              <SkeletonTable rows={5} label="Loading remote access" />
            </Card>
          }
        >
          <RemoteAccessContent ctx={ctx} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}

async function RemoteAccessContent({ ctx }: { ctx: ConsoleContext }) {
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
  if (error || !settings) {
    return (
      <Alert tone="error" title="Remote access couldn't be loaded">
        <p>{error}</p>
        <p>Check that the coordinator is running, then reload.</p>
      </Alert>
    );
  }
  const names = new Map(nodes.map((node) => [node.id, node.display_name || node.name]));
  const active = nodes.filter((node) => !node.revoked && !node.deleted);
  const pending = hostKeys.filter((key) => key.pending_fingerprint);
  const state = GATEWAY_STATE[settings.gateway_state];

  return (
    <>
      <Section
        id="gateway"
        title="Gateway"
        description="The device browsers connect through. Devices trust the organisation's SSH CA only for connections from the gateway, and only when their operator opted in."
        actions={<StatusPill tone={state.tone}>{state.label}</StatusPill>}
      >
        <dl className="detail-list">
          <dt>Gateway device</dt>
          <dd>{settings.gateway_name || "None chosen"}</dd>
          <dt>Browser address</dt>
          <dd className="mono">{settings.gateway_url || "—"}</dd>
          <dt>Limits</dt>
          <dd>
            Tickets last {settings.ticket_ttl_seconds} seconds and work once. Sessions last at most{" "}
            {settings.max_session_seconds / 60} minutes and end after {settings.idle_timeout_seconds / 60} idle
            minutes.
          </dd>
          <dt>Organisation SSH user CA</dt>
          <dd className="mono">{settings.ca_public_key || "Created when an owner first saves a gateway"}</dd>
        </dl>
        <GatewaySettingsForm
          devices={active.map((node) => ({ id: node.id, label: node.display_name || node.name }))}
          gatewayNodeId={settings.gateway_node_id}
          gatewayUrl={settings.gateway_url}
          disabledReason={permissionReason(ctx.role, "manage_security")}
        />
        <p className="muted">
          On a Linux agent the operator opts in with <span className="mono">BLAKTAIL_SSHD_DROPIN</span> and{" "}
          <span className="mono">BLAKTAIL_SSH_USER_CA</span>. See{" "}
          <Link href="https://github.com/jusso-dev/BlakTail/blob/main/docs/remote-access.md">docs/remote-access.md</Link>.
        </p>
      </Section>

      <Section
        id="host-keys"
        title="SSH host keys"
        description="Each device's agent reports its Ed25519 host key, and the gateway refuses any other. A changed key blocks sessions until someone who manages devices checks it on the device and accepts it."
      >
        {pending.length > 0 ? (
          <Alert tone="warning" title={`${pending.length} device${pending.length === 1 ? "" : "s"} reported a new host key`}>
            Sessions to {pending.length === 1 ? "it" : "them"} are blocked until the new key is checked and accepted.
          </Alert>
        ) : null}
        {hostKeys.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No host keys reported yet"
            body="Agents report /etc/ssh/ssh_host_ed25519_key.pub after their next sync."
          />
        ) : (
          <Table label="SSH host keys" mobile="stack">
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
                  <Td label="Device">
                    <Link href={`/devices/${key.node_id}`}>{names.get(key.node_id) ?? key.node_id}</Link>
                  </Td>
                  <Td label="Pinned key" className="mono cell-break">
                    {key.fingerprint}
                  </Td>
                  <Td label="Pending change">
                    {key.pending_fingerprint ? (
                      <div className="stack tight">
                        <StatusPill tone="warning">New key reported</StatusPill>
                        <span className="mono cell-break">{key.pending_fingerprint}</span>
                        <span className="cell-sub">Reported {formatDateTime(key.pending_reported_at)}</span>
                        <AcceptHostKeyButton
                          nodeId={key.node_id}
                          fingerprint={key.pending_fingerprint}
                          deviceName={names.get(key.node_id) ?? key.node_id}
                          disabledReason={permissionReason(ctx.role, "manage_peers")}
                        />
                      </div>
                    ) : (
                      <span className="muted">None</span>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section id="sessions" title="Recent sessions" description="Every session is audited with its reason and how much data passed through.">
        {sessionsDenied ? (
          <Alert tone="info">{sessionsDenied}</Alert>
        ) : sessions.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No sessions yet"
            body="Open a device and choose Open terminal to start one."
            action={
              <Link className="button secondary ui-button" href="/devices">
                Go to Devices
              </Link>
            }
          />
        ) : (
          <Table label="Recent sessions" mobile="stack">
            <thead>
              <tr>
                <th scope="col">Status</th>
                <th scope="col">Person</th>
                <th scope="col">Device and account</th>
                <th scope="col">Reason</th>
                <th scope="col">Started</th>
                <th scope="col">Ended</th>
                <th scope="col">Data in / out</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {sessions.map((session) => (
                <tr key={session.id}>
                  <Td label="Status">
                    <StatusPill tone={SESSION_STATE[session.status].tone}>{SESSION_STATE[session.status].label}</StatusPill>
                    <span className="cell-sub">{session.kind.toUpperCase()}</span>
                  </Td>
                  <Td label="Person">{session.user_name || session.user_id}</Td>
                  <Td label="Device">
                    <span className="mono">{session.os_user}</span>@
                    {names.get(session.target_node_id) ?? session.target_node_id}
                  </Td>
                  <Td label="Reason">{session.reason}</Td>
                  <Td label="Started">{formatDateTime(session.redeemed_at ?? session.created_at)}</Td>
                  <Td label="Ended">
                    {formatDateTime(session.ended_at)}
                    {session.end_reason ? <span className="cell-sub">{session.end_reason}</span> : null}
                  </Td>
                  <Td label="Data">
                    {bytes(session.bytes_to_target)} / {bytes(session.bytes_from_target)}
                  </Td>
                  <Td>
                    {(session.status === "active" || session.status === "issued") &&
                    can(ctx.role, "use_remote_sessions") ? (
                      <div className="cell-actions">
                        <RevokeSessionButton
                          sessionId={session.id}
                          label={`${session.os_user}@${names.get(session.target_node_id) ?? "device"}`}
                        />
                      </div>
                    ) : null}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>
    </>
  );
}
