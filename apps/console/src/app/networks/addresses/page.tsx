import { Suspense } from "react";
import Link from "next/link";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import {
  ReleaseReservationButton,
  ReserveAddressForm,
} from "@/components/address-reservations";
import {
  RenumberPlanForm,
  StagedRenumber,
  type RenumberDevice,
} from "@/components/address-renumber";
import { EmptyState } from "@/components/empty-state";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { StatusPill, type BadgeTone } from "@/components/ui/badge";
import { LocalTime } from "@/components/ui/local-time";
import { MonoValue } from "@/components/ui/mono-value";
import { PermissionNotice } from "@/components/ui/permission-notice";
import { Section } from "@/components/ui/section";
import { SkeletonTable } from "@/components/ui/skeleton";
import { Table, Td } from "@/components/ui/table";
import { getIpam, type AddressState, type IpamView, type ReservationState } from "@/lib/coord-ipam";
import { unixNow } from "@/lib/format-time";
import { can, permissionReason } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

const addressStateLabel: Record<AddressState, { label: string; tone: BadgeTone }> = {
  active: { label: "In use", tone: "success" },
  retiring: { label: "Retiring (renumber window)", tone: "warning" },
  revoked: { label: "Revoked device", tone: "muted" },
  tombstoned: { label: "Deleted, in grace period", tone: "warning" },
  released: { label: "Released, in grace period", tone: "warning" },
};

const reservationStateLabel: Record<ReservationState, { label: string; tone: BadgeTone }> = {
  held: { label: "Held", tone: "brand" },
  waiting: { label: "Waiting for device", tone: "warning" },
  assigned: { label: "Assigned as reserved", tone: "success" },
  pending_reenrolment: { label: "Applies on re-enrolment", tone: "warning" },
  conflict: { label: "Conflict", tone: "danger" },
};

function date(at: number | null) {
  return <LocalTime value={at} fallback="—" />;
}

async function AddressesBody({ ctx }: { ctx: ConsoleContext }) {
  let view: IpamView | null = null;
  let error: string | null = null;
  try {
    view = await getIpam(ctx);
  } catch (err) {
    error = errorText(err, "Could not load address pools.");
  }
  if (!view) {
    return (
      <Alert tone="error" title="Couldn't load address pools">
        {error}
      </Alert>
    );
  }
  const canManage = can(ctx.role, "manage_networks");
  const graceDays = Math.round(view.reuse_grace_seconds / 86400);
  const ipv4Pool = view.pools.find((pool) => pool.family === "ipv4")?.cidr ?? "";
  const renumberDevices: RenumberDevice[] = view.addresses
    .filter((entry) => entry.state === "active" && entry.node_id)
    .map((entry) => ({
      nodeId: entry.node_id ?? "",
      name: entry.node_name ?? entry.address,
      address: entry.address,
    }));

  return (
    <>
      <Section
        id="pools"
        title="Pools"
        description={`Deleted devices' addresses aren't reused for ${graceDays} days.`}
      >
        <Table label="Address pools" mobile="stack">
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
                <Td label="Family">{pool.family === "ipv6" ? "IPv6" : "IPv4"}</Td>
                <Td label="Pool">
                  <div>
                    <MonoValue value={pool.cidr} copy copyLabel={`Copy ${pool.family} pool`} />
                    {pool.note ? <div className="cell-sub">{pool.note}</div> : null}
                  </div>
                </Td>
                <Td label="In use">{pool.used}</Td>
                <Td label="Reserved">{pool.reserved}</Td>
                <Td label="In grace">{pool.in_grace}</Td>
                <Td label="Available">
                  <div>
                    {pool.available} of {pool.usable}
                  </div>
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
        <p className="muted">
          Next automatic allocation:{" "}
          {view.next_free ? (
            <MonoValue value={view.next_free} />
          ) : (
            "none, the pool is exhausted"
          )}
          .
        </p>
      </Section>

      <Section
        id="renumber"
        title="Renumbering"
        description="Grow the IPv4 pool or move devices to new addresses without breaking connections: moved devices answer on both addresses for a window, then the old address retires. Device names, keys and IPv6 addresses tied to unchanged IPv4 addresses stay the same."
      >
        {view.renumber.staged ? (
          <StagedRenumber
            organisationId={ctx.organisationId}
            role={ctx.role}
            plan={view.renumber.staged}
            now={unixNow()}
          />
        ) : canManage ? (
          <RenumberPlanForm
            organisationId={ctx.organisationId}
            role={ctx.role}
            currentPool={ipv4Pool}
            prefixRange={view.pool_prefix_range}
            defaultWindowSeconds={view.renumber.default_window_seconds}
            minWindowSeconds={view.renumber.min_window_seconds}
            devices={renumberDevices}
          />
        ) : null}
        {view.renumber.history.length ? (
          <>
            <h3>Recent plans</h3>
            <Table label="Recent renumber plans" mobile="stack">
              <thead>
                <tr>
                  <th>Started</th>
                  <th>Change</th>
                  <th>Devices</th>
                  <th>Outcome</th>
                </tr>
              </thead>
              <tbody>
                {view.renumber.history.map((plan) => (
                  <tr key={plan.id}>
                    <Td label="Started">
                      <div>
                        {date(plan.created_at)}
                        <div className="cell-sub">{plan.created_by}</div>
                      </div>
                    </Td>
                    <Td label="Change">
                      <div>
                        <MonoValue
                          wrap
                          value={
                            plan.previous_pool === plan.target_pool
                              ? plan.target_pool
                              : `${plan.previous_pool} → ${plan.target_pool}`
                          }
                        />
                        {plan.reason ? <div className="cell-sub">{plan.reason}</div> : null}
                      </div>
                    </Td>
                    <Td label="Devices">{plan.moves.length}</Td>
                    <Td label="Outcome">
                      <div>
                        <StatusPill tone={plan.state === "completed" ? "success" : "muted"}>
                          {plan.state === "completed" ? "Completed" : "Rolled back"}
                        </StatusPill>
                        <div className="cell-sub">
                          {date(plan.finished_at)}
                          {plan.finished_by ? ` by ${plan.finished_by}` : ""}
                        </div>
                      </div>
                    </Td>
                  </tr>
                ))}
              </tbody>
            </Table>
          </>
        ) : null}
      </Section>

      <Section id="conflicts" title="Conflicts">
        {view.conflicts.length === 0 ? (
          <p className="muted">No address conflicts.</p>
        ) : (
          <ul className="stack">
            {view.conflicts.map((conflict) => (
              <li key={`${conflict.kind}:${conflict.address}`}>
                <StatusPill tone="danger">{conflict.kind.replaceAll("_", " ")}</StatusPill>{" "}
                <MonoValue value={conflict.address} />: {conflict.detail}
              </li>
            ))}
          </ul>
        )}
      </Section>

      <Section
        id="reservations"
        title="Reservations"
        description="Keep an address out of automatic allocation, or give a specific device a stable address."
      >
        {view.reservations.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No reservations"
            body="Reserved addresses appear here with who they're bound to and whether they're in use."
          />
        ) : (
          <Table label="Address reservations" mobile="stack">
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
                    <Td label="Address">
                      <div>
                        <MonoValue value={reservation.address} copy copyLabel="Copy address" />
                        <div className="cell-sub mono">{reservation.ipv6}</div>
                      </div>
                    </Td>
                    <Td label="Bound to">
                      <div>
                        {reservation.bound_name ?? null}
                        {reservation.bound_key_fingerprint ? (
                          <div className="cell-sub">
                            key <MonoValue value={reservation.bound_key_fingerprint} />
                          </div>
                        ) : null}
                        {!reservation.bound_name && !reservation.bound_key_fingerprint ? (
                          <span className="muted">Nobody</span>
                        ) : null}
                      </div>
                    </Td>
                    <Td label="State">
                      <div>
                        <StatusPill tone={state.tone}>{state.label}</StatusPill>
                        <div className="cell-sub">{reservation.detail}</div>
                      </div>
                    </Td>
                    <Td label="Reason">{reservation.reason || "—"}</Td>
                    <Td label="Created">
                      <div>
                        {date(reservation.created_at)}
                        <div className="cell-sub">{reservation.created_by}</div>
                      </div>
                    </Td>
                    <Td>
                      <div className="cell-actions">
                        <ReleaseReservationButton
                          organisationId={ctx.organisationId}
                          role={ctx.role}
                          reservationId={reservation.id}
                          etag={reservation.etag}
                          address={reservation.address}
                        />
                      </div>
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Section>

      {canManage ? (
        <Section id="reserve" title="Reserve an address">
          <ReserveAddressForm
            organisationId={ctx.organisationId}
            role={ctx.role}
            suggested={view.next_free}
          />
        </Section>
      ) : null}

      <Section id="assigned" title="Assigned addresses">
        {view.addresses.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No addresses assigned yet"
            body="Each device gets an IPv4 and a matching IPv6 address when it enrols."
          />
        ) : (
          <Table label="Assigned addresses" mobile="stack">
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
                    <Td label="IPv4">
                      <MonoValue value={entry.address} />
                    </Td>
                    <Td label="IPv6">
                      <MonoValue value={entry.ipv6} />
                    </Td>
                    <Td label="Owner">
                      {entry.node_name ?? <span className="muted">Deleted device</span>}
                    </Td>
                    <Td label="State">
                      <div>
                        <StatusPill tone={state.tone}>{state.label}</StatusPill>
                        {entry.reservation_id ? <div className="cell-sub">Reserved</div> : null}
                      </div>
                    </Td>
                    <Td label="Reusable from">
                      {entry.state === "active" || entry.state === "revoked"
                        ? "While the device exists"
                        : date(entry.reusable_at)}
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Section>
    </>
  );
}

export default async function AddressesPage() {
  const ctx = await requireConsoleContext();
  const denied = permissionReason(ctx.role, "manage_networks");

  return (
    <ConsoleShell ctx={ctx} current="/networks/addresses">
      <div className="stack">
        <Link className="back-link" href="/networks">
          ← Networks
        </Link>
        <PageHeader
          eyebrow={ctx.organisationName}
          title="Addresses"
          description="Overlay address pools for this organisation. Every device keeps one IPv4 and one matching IPv6 address."
        />
        {denied ? (
          <PermissionNotice reason={denied}>
            You can still see pools, reservations and renumber history.
          </PermissionNotice>
        ) : null}
        <Suspense
          fallback={
            <Section title="Pools">
              <SkeletonTable rows={2} label="Loading address pools" />
            </Section>
          }
        >
          <AddressesBody ctx={ctx} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}
