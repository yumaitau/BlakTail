import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { RemoteTerminal } from "@/components/remote-terminal";
import { CoordRequestError, getPeerDetail, type PeerDetail } from "@/lib/coord-peers";
import { getRemoteSettings, listHostKeys, type HostKey, type RemoteSettings } from "@/lib/coord-remote";
import { permissionReason, roleLabel } from "@/lib/roles";
import {
  organisationContext,
  requirePersonSessionContext,
  type ConsoleContext,
} from "@/lib/session";

async function findDevice(
  contexts: ConsoleContext[],
  nodeId: string,
): Promise<{ ctx: ConsoleContext; detail: PeerDetail } | { error: string } | null> {
  for (const ctx of contexts) {
    try {
      return { ctx, detail: await getPeerDetail(ctx, nodeId) };
    } catch (error) {
      if (error instanceof CoordRequestError && error.status === 404) continue;
      return { error: error instanceof Error ? error.message : "Could not load this device." };
    }
  }
  return null;
}

function blocker(
  ctx: ConsoleContext,
  detail: PeerDetail,
  settings: RemoteSettings | null,
  hostKey: HostKey | undefined,
): string | null {
  const denied = permissionReason(ctx.role, "use_remote_sessions");
  if (denied) return denied;
  if (detail.lifecycle.state !== "active") {
    return `This device is ${detail.lifecycle.state}; sessions cannot start.`;
  }
  if (!settings?.configured) {
    return "Browser remote access is not set up for this organisation. An owner chooses the gateway on the Remote access page.";
  }
  if (settings.gateway_state !== "online") {
    return `The remote-access gateway is ${settings.gateway_state.replace("_", " ")}.`;
  }
  if (settings.gateway_node_id === detail.node.id) {
    return "This device is the gateway itself.";
  }
  if (!hostKey) {
    return "This device has not reported an SSH host key. Its agent reports one when /etc/ssh/ssh_host_ed25519_key.pub exists.";
  }
  if (hostKey.pending_fingerprint) {
    return `This device reported a new SSH host key (${hostKey.pending_fingerprint}). An administrator must check and accept it on the Remote access page first.`;
  }
  return null;
}

export default async function DeviceTerminalPage({
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
  const found = /^[0-9a-f-]{36}$/i.test(nodeId) ? await findDevice(candidates, nodeId) : null;

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
  const label = detail.node.display_name || detail.node.name;
  let settings: RemoteSettings | null = null;
  let hostKey: HostKey | undefined;
  let loadError: string | null = null;
  try {
    const [loaded, keys] = await Promise.all([getRemoteSettings(ctx), listHostKeys(ctx)]);
    settings = loaded;
    hostKey = keys.find((key) => key.node_id === detail.node.id);
  } catch (error) {
    loadError = error instanceof Error ? error.message : "Could not load remote access settings.";
  }
  const disabledReason = loadError ?? blocker(ctx, detail, settings, hostKey);

  return (
    <ConsoleShell ctx={person} current="/devices">
      <div className="stack">
        <p>
          <Link href={`/devices/${detail.node.id}`}>← {label}</Link>
        </p>
        <PageHeader
          eyebrow={ctx.organisationName}
          title={`Terminal: ${label}`}
          description="An SSH session through this organisation's onshore gateway. The gateway is a BlakTail device, so access policy and SSH rules decide what it can reach. The session needs a fresh ticket, a recent sign-in and an access reason; it lasts at most 30 minutes and ends after 10 minutes without input."
        />
        <section className="panel stack" aria-labelledby="terminal-title">
          <h2 id="terminal-title">Session</h2>
          {hostKey && !hostKey.pending_fingerprint ? (
            <p className="muted">
              Pinned host key <span className="mono">{hostKey.fingerprint}</span>. The gateway refuses any other key.
            </p>
          ) : null}
          <RemoteTerminal
            organisationId={ctx.organisationId}
            organisationName={ctx.organisationName}
            roleName={roleLabel(ctx.role)}
            nodeId={detail.node.id}
            deviceName={label}
            disabledReason={disabledReason}
          />
        </section>
        <section className="panel stack" aria-labelledby="terminal-record-title">
          <h2 id="terminal-record-title">What is recorded</h2>
          <p className="muted">
            The audit log records who opened the session, the device, the account, your reason,
            start and end times, why it ended and how many bytes moved. Keystrokes and screen
            output are not recorded or logged.
          </p>
        </section>
      </div>
    </ConsoleShell>
  );
}
