import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import {
  ReleaseReservationButton,
  ReserveAddressForm,
} from "@/components/address-reservations";
import { PageHeader } from "@/components/page-header";
import { getIpam, type AddressState, type IpamView, type ReservationState } from "@/lib/coord-ipam";
import { can, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

const addressStateLabel: Record<AddressState, { label: string; badge: string }> = {
  active: { label: "In use", badge: "online" },
  revoked: { label: "Revoked device", badge: "offline" },
  tombstoned: { label: "Deleted, in grace period", badge: "pending" },
  released: { label: "Released, in grace period", badge: "pending" },
};

const reservationStateLabel: Record<ReservationState, { label: string; badge: string }> = {
  held: { label: "Held", badge: "network" },
  waiting: { label: "Waiting for device", badge: "pending" },
  assigned: { label: "Assigned as reserved", badge: "online" },
  pending_reenrolment: { label: "Applies on re-enrolment", badge: "pending" },
  conflict: { label: "Conflict", badge: "warn" },
};

function date(at: number | null): string {
  if (!at) return "—";
  return new Date(at * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Australia/Sydney",
  });
}

export default async function AddressesPage() {
  const ctx = await requireConsoleContext();
  let view: IpamView | null = null;
  let error: string | null = null;
  try {
    view = await getIpam(ctx);
  } catch (err) {
    error = err instanceof Error ? err.message : "Could not load address pools.";
  }
  const canManage = can(ctx.role, "manage_networks");
  const graceDays = view ? Math.round(view.reuse_grace_seconds / 86400) : 7;

  return (
    <ConsoleShell ctx={ctx} current="/networks/addresses">
      <div className="stack">
        <p>
          <Link href="/networks">← Networks</Link>
        </p>
        <PageHeader
          eyebrow={ctx.organisationName}
          title="Addresses"
          description={`Overlay address pools for this organisation. Every device keeps one IPv4 and one matching IPv6 address; deleted devices' addresses are not reused for ${graceDays} days.`}
        />
        {error ? (
          <p className="error" role="alert">
            {error}
          </p>
        ) : null}
        {view ? (
          <>
            <div className="panel stack">
              <h2>Pools</h2>
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>Family</th>
                      <th>Pool</th>
                      <th>In use</th>
                      <th>Reserved</th>
                      <th>In grace period</th>
                      <th>Available</th>
                    </tr>
                  </thead>
                  <tbody>
                    {view.pools.map((pool) => (
                      <tr key={pool.family}>
                        <td>{pool.family === "ipv6" ? "IPv6" : "IPv4"}</td>
                        <td>
                          <span className="mono">{pool.cidr}</span>
                          <div className="muted">{pool.note}</div>
                        </td>
                        <td>{pool.used}</td>
                        <td>{pool.reserved}</td>
                        <td>{pool.in_grace}</td>
                        <td>
                          {pool.available} of {pool.usable}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="muted">
                Next automatic allocation:{" "}
                <span className="mono">{view.next_free ?? "none — pool exhausted"}</span>.
                Renumbering and pool expansion are not available yet; see the
                IPAM documentation for the planned staged dual-address process.
              </p>
            </div>

            <div className="panel stack">
              <h2>Conflicts</h2>
              {view.conflicts.length === 0 ? (
                <p className="muted">No address conflicts.</p>
              ) : (
                <ul className="stack">
                  {view.conflicts.map((conflict) => (
                    <li key={`${conflict.kind}:${conflict.address}`}>
                      <span className="badge warn">{conflict.kind.replaceAll("_", " ")}</span>{" "}
                      <span className="mono">{conflict.address}</span> — {conflict.detail}
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="panel stack">
              <h2>Reservations</h2>
              {view.reservations.length === 0 ? (
                <p className="muted">
                  No reservations. Reserve an address to keep it out of automatic
                  allocation or to give a specific device a stable address.
                </p>
              ) : (
                <div className="table-wrap">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>Address</th>
                        <th>Bound to</th>
                        <th>State</th>
                        <th>Reason</th>
                        <th>Created</th>
                        <th>
                          <span className="visually-hidden">Actions</span>
                        </th>
                      </tr>
                    </thead>
                    <tbody>
                      {view.reservations.map((reservation) => {
                        const state = reservationStateLabel[reservation.state];
                        return (
                          <tr key={reservation.id}>
                            <td className="mono">
                              {reservation.address}
                              <div className="muted">{reservation.ipv6}</div>
                            </td>
                            <td>
                              {reservation.bound_name ?? null}
                              {reservation.bound_key_fingerprint ? (
                                <div className="mono muted">key {reservation.bound_key_fingerprint}</div>
                              ) : null}
                              {!reservation.bound_name && !reservation.bound_key_fingerprint
                                ? "Nobody"
                                : null}
                            </td>
                            <td>
                              <span className={`badge ${state.badge}`}>{state.label}</span>
                              <div className="muted">{reservation.detail}</div>
                            </td>
                            <td>{reservation.reason || "—"}</td>
                            <td>
                              {date(reservation.created_at)}
                              <div className="muted">{reservation.created_by}</div>
                            </td>
                            <td>
                              <ReleaseReservationButton
                                organisationId={ctx.organisationId}
                                role={ctx.role}
                                reservationId={reservation.id}
                                etag={reservation.etag}
                                address={reservation.address}
                              />
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
              {canManage ? (
                <ReserveAddressForm
                  organisationId={ctx.organisationId}
                  organisationName={ctx.organisationName}
                  role={ctx.role}
                  suggested={view.next_free}
                />
              ) : (
                <p className="muted">
                  {roleLabel(ctx.role)}s can view addresses; owners, admins and
                  network admins can reserve and release them.
                </p>
              )}
            </div>

            <div className="panel stack">
              <h2>Assigned addresses</h2>
              {view.addresses.length === 0 ? (
                <p className="muted">No device has an address yet.</p>
              ) : (
                <div className="table-wrap">
                  <table className="table">
                    <thead>
                      <tr>
                        <th>IPv4</th>
                        <th>IPv6</th>
                        <th>Owner</th>
                        <th>State</th>
                        <th>Reusable from</th>
                      </tr>
                    </thead>
                    <tbody>
                      {view.addresses.map((entry) => {
                        const state = addressStateLabel[entry.state];
                        return (
                          <tr key={`${entry.address}:${entry.node_id ?? ""}`}>
                            <td className="mono">{entry.address}</td>
                            <td className="mono">{entry.ipv6}</td>
                            <td>{entry.node_name ?? <span className="muted">Deleted device</span>}</td>
                            <td>
                              <span className={`badge ${state.badge}`}>{state.label}</span>
                              {entry.reservation_id ? <div className="muted">Reserved</div> : null}
                            </td>
                            <td>
                              {entry.state === "active" || entry.state === "revoked"
                                ? "While the device exists"
                                : date(entry.reusable_at)}
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </>
        ) : null}
      </div>
    </ConsoleShell>
  );
}
