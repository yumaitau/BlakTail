import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { PqPolicyForm } from "@/components/pq-policy-form";
import { PqPeerTable } from "@/components/pq-peer-table";
import { getPqOverview, type PqOverview } from "@/lib/coord-pq";
import { permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

export default async function TunnelProtectionPage() {
  const ctx = await requireConsoleContext();
  let overview: PqOverview | null = null;
  let error: string | null = null;
  try {
    overview = await getPqOverview(ctx);
  } catch (err) {
    error = err instanceof Error ? err.message : "Could not load tunnel protection.";
  }
  const denied = permissionReason(ctx.role, "manage_security");
  const names = new Map(overview?.devices.map((device) => [device.id, device.name]) ?? []);

  return (
    <ConsoleShell ctx={ctx} current="/tunnel-protection">
      <div className="stack">
        <PageHeader
          title="Tunnel protection"
          description={`Optional hybrid post-quantum pre-shared keys for WireGuard in ${ctx.organisationName}. Off by default. Each row shows what a device's agent reports it actually negotiated with one peer.`}
        />
        {error ? (
          <div className="panel">
            <p className="error" role="alert">
              {error}
            </p>
          </div>
        ) : null}
        {overview ? (
          <>
            <section className="panel stack" aria-labelledby="pq-limits-title">
              <h2 id="pq-limits-title">What this does and does not do</h2>
              <ul className="audit-details">
                <li>
                  Devices that both run a current agent derive a fresh WireGuard pre-shared key
                  every two minutes from ML-KEM-768 and X25519, exchanged inside their existing
                  tunnel. The coordinator never sees the key.
                </li>
                <li>
                  This adds protection for recorded traffic against a future quantum computer.
                  Device authentication stays classical WireGuard (Curve25519).
                </li>
                <li>
                  It has not had an independent cryptographic review. Treat it as a hardening
                  option, not a guarantee.
                </li>
                <li>
                  Blocking under require is enforced by Linux agents. macOS agents report the
                  state but cannot block; the Linux side of a pair still does.
                </li>
              </ul>
              <p className="muted">
                Details and limits: <a href="https://github.com/jusso-dev/BlakTail/blob/main/docs/post-quantum.md">docs/post-quantum.md</a>.
              </p>
            </section>

            <section className="panel stack" aria-labelledby="pq-policy-title">
              <h2 id="pq-policy-title">Policy</h2>
              <PqPolicyForm
                policy={overview.policy}
                organisationName={ctx.organisationName}
                roleLabel={roleLabel(ctx.role)}
                disabledReason={denied ? `Only owners change tunnel cryptography. ${denied}` : null}
              />
            </section>

            <section className="panel stack" aria-labelledby="pq-devices-title">
              <h2 id="pq-devices-title">Agent support</h2>
              {overview.devices.length === 0 ? (
                <EmptyState
                  title="No devices yet"
                  body="Enrol a device; its agent reports whether it supports hybrid keys."
                  action={<Link href="/join-keys">Create a join key</Link>}
                />
              ) : (
                <div className="table-wrap">
                  <table className="table">
                    <caption className="muted">
                      Whether each agent advertises the pq-psk capability
                    </caption>
                    <thead>
                      <tr>
                        <th scope="col">Device</th>
                        <th scope="col">Hybrid PQ support</th>
                      </tr>
                    </thead>
                    <tbody>
                      {overview.devices.map((device) => (
                        <tr key={device.id}>
                          <td>
                            <Link href={`/devices/${device.id}`}>{device.name}</Link>
                          </td>
                          <td>
                            {device.capable
                              ? "Supported"
                              : "Not advertised (older, opted-out or unsupported agent)"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </section>

            <section className="panel stack" aria-labelledby="pq-peers-title">
              <h2 id="pq-peers-title">Per-peer protection</h2>
              <PqPeerTable rows={overview.peers} deviceNames={names} showDevice />
            </section>
          </>
        ) : null}
      </div>
    </ConsoleShell>
  );
}
