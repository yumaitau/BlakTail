import { errorText } from "@/lib/server-errors";
import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { RemoteDesktop } from "@/components/remote-desktop";
import { CoordRequestError, getPeerDetail, type PeerDetail } from "@/lib/coord-peers";
import { getRemoteSettings, type RemoteSettings } from "@/lib/coord-remote";
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
      return { error: errorText(error, "Could not load this device.") };
    }
  }
  return null;
}

export default async function DeviceDesktopPage({
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
  let disabledReason = permissionReason(ctx.role, "use_remote_sessions");
  if (!disabledReason) {
    try {
      settings = await getRemoteSettings(ctx);
    } catch (error) {
      disabledReason = errorText(error, "Could not load remote access settings.");
    }
  }
  if (!disabledReason && detail.lifecycle.state !== "active") {
    disabledReason = `This device is ${detail.lifecycle.state}; sessions cannot start.`;
  }
  if (!disabledReason && (!settings?.configured || settings.gateway_state !== "online")) {
    disabledReason = "The remote-access gateway is not set up or not online.";
  }

  return (
    <ConsoleShell ctx={person} current="/devices">
      <div className="stack">
        <p>
          <Link href={`/devices/${detail.node.id}`}>← {label}</Link>
        </p>
        <PageHeader
          eyebrow={ctx.organisationName}
          title={`Remote desktop: ${label}`}
          description="RDP to a Windows or xrdp host through the onshore gateway and its guacd sidecar. Policy must let the gateway reach TCP 3389 on this device. The device's own sign-in is enforced; the password is typed per session and never stored."
        />
        <section className="panel stack" aria-labelledby="desktop-title">
          <h2 id="desktop-title">Session</h2>
          <RemoteDesktop
            organisationId={ctx.organisationId}
            organisationName={ctx.organisationName}
            roleName={roleLabel(ctx.role)}
            nodeId={detail.node.id}
            deviceName={label}
            disabledReason={disabledReason}
          />
        </section>
        <section className="panel stack" aria-labelledby="desktop-limits-title">
          <h2 id="desktop-limits-title">Limits</h2>
          <p className="muted">
            The RDP server certificate is not pinned: the gateway relies on the WireGuard identity
            of the device&apos;s overlay address instead. Screen contents are not recorded; only
            who, when, the account, your reason and byte counts are audited.
          </p>
        </section>
      </div>
    </ConsoleShell>
  );
}
