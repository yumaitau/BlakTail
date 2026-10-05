import { Suspense } from "react";
import Link from "next/link";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { PqPolicyForm } from "@/components/pq-policy-form";
import { PqPeerTable } from "@/components/pq-peer-table";
import { Alert } from "@/components/ui/alert";
import { StatusPill } from "@/components/ui/badge";
import { PermissionNotice } from "@/components/ui/permission-notice";
import { Section } from "@/components/ui/section";
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton";
import { Table, Td } from "@/components/ui/table";
import { getPqOverview, type PqOverview } from "@/lib/coord-pq";
import { permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

export default async function TunnelProtectionPage() {
  const ctx = await requireConsoleContext();
  const denied = permissionReason(ctx.role, "manage_security");

  return (
    <ConsoleShell ctx={ctx} current="/tunnel-protection">
      <div className="stack">
        <PageHeader
          eyebrow={ctx.organisationName}
          title="Tunnel protection"
          description="Optional hybrid post-quantum pre-shared keys for WireGuard. Off by default. Each peer row shows what a device's agent reports it actually negotiated."
          actions={
            <a
              className="button secondary"
              href="https://github.com/jusso-dev/BlakTail/blob/main/docs/post-quantum.md"
              rel="noreferrer"
              target="_blank"
            >
              Read the limits
            </a>
          }
        />
        {denied ? (
          <PermissionNotice reason={`Only owners change tunnel cryptography. ${denied}`} />
        ) : null}
        <Suspense
          fallback={
            <>
              <Section title="Policy">
                <Skeleton lines={3} label="Loading tunnel protection" />
              </Section>
              <Section title="Agent support">
                <SkeletonTable rows={4} label="Loading agent support" />
              </Section>
            </>
          }
        >
          <TunnelWorkspace ctx={ctx} denied={denied} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}

async function TunnelWorkspace({ ctx, denied }: { ctx: ConsoleContext; denied: string | null }) {
  let overview: PqOverview | null = null;
  let error: string | null = null;
  try {
    overview = await getPqOverview(ctx);
  } catch (err) {
    error = errorText(err, "Could not load tunnel protection.");
  }
  if (!overview) {
    return (
      <Alert tone="error" title="Tunnel protection couldn't be loaded">
        {error}
      </Alert>
    );
  }
  const names = new Map(overview.devices.map((device) => [device.id, device.name]));
  const capable = overview.devices.filter((device) => device.capable).length;

  return (
    <>
      <Section id="limits" title="What this does and does not do">
        <ul className="audit-details">
          <li>
            Devices that both run a current agent derive a fresh WireGuard pre-shared key every
            two minutes from ML-KEM-768 and X25519, exchanged inside their existing tunnel. The
            coordinator never sees the key.
          </li>
          <li>
            This adds protection for recorded traffic against a future quantum computer. Device
            authentication stays classical WireGuard (Curve25519).
          </li>
          <li>
            It has not had an independent cryptographic review. Treat it as a hardening option,
            not a guarantee.
          </li>
          <li>
            Blocking under require is enforced by Linux agents. macOS agents report the state but
            cannot block; the Linux side of a pair still does.
          </li>
        </ul>
      </Section>

      <Section id="policy" title="Policy">
        <PqPolicyForm
          policy={overview.policy}
          organisationName={ctx.organisationName}
          roleLabel={roleLabel(ctx.role)}
          disabledReason={denied}
        />
      </Section>

      <Section
        id="support"
        title="Agent support"
        description={
          overview.devices.length
            ? `${capable} of ${overview.devices.length} devices advertise the pq-psk capability.`
            : undefined
        }
      >
        {overview.devices.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No devices yet"
            body="Enrol a device; its agent reports whether it supports hybrid keys."
            action={
              <Link className="button secondary" href="/join-keys">
                Create a join key
              </Link>
            }
          />
        ) : (
          <Table label="Agent support for hybrid keys" mobile="stack">
            <thead>
              <tr>
                <th scope="col">Device</th>
                <th scope="col">Hybrid PQ support</th>
              </tr>
            </thead>
            <tbody>
              {overview.devices.map((device) => (
                <tr key={device.id}>
                  <Td label="Device">
                    <Link href={`/devices/${device.id}`}>{device.name}</Link>
                  </Td>
                  <Td label="Hybrid PQ">
                    {device.capable ? (
                      <StatusPill tone="success">Supported</StatusPill>
                    ) : (
                      <div>
                        <StatusPill tone="muted">Not advertised</StatusPill>
                        <div className="cell-sub">Older, opted-out or unsupported agent</div>
                      </div>
                    )}
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </Section>

      <Section id="peers" title="Per-peer protection">
        <PqPeerTable rows={overview.peers} deviceNames={names} showDevice />
      </Section>
    </>
  );
}
