import Link from "next/link";
import { Suspense } from "react";
import { ConsoleShell } from "@/components/console-shell";
import { DeviceActions } from "@/components/device-actions";
import { PageHeader } from "@/components/page-header";
import { Alert } from "@/components/ui/alert";
import { Section } from "@/components/ui/section";
import { Skeleton, SkeletonTable } from "@/components/ui/skeleton";
import { WgOnlyManager } from "@/components/wg-only-manager";
import { listAllNodes, listAllWgOnlyPeers, type NetworkNode } from "@/lib/coord";
import { listMemberships } from "@/lib/oidc";
import { can } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

function needsAttention(node: NetworkNode): boolean {
  return (
    !node.deleted &&
    (node.revoked ||
      node.suspended ||
      node.expired ||
      node.expires_soon ||
      node.advertised_routes.some((route) => !node.approved_routes.includes(route)))
  );
}

/** Coordinator-backed part of the page; streams in behind a skeleton. */
async function DeviceInventory({ ctx }: { ctx: ConsoleContext }) {
  const [inventory, memberships, unmanaged] = await Promise.all([
    listAllNodes(ctx),
    Promise.all(
      ctx.organisations.map((organisation) =>
        listMemberships(organisation.organisationId).catch(() => []),
      ),
    ).then((rows) => rows.flat().filter((row) => row.status === "active")),
    listAllWgOnlyPeers(ctx),
  ]);
  const blockedErrors = ctx.blockedOrganisations.map(
    (organisation) =>
      `${organisation.organisationName}: an owner must resolve the linked-account role conflict.`,
  );
  const live = inventory.nodes.filter((node) => !node.deleted);
  const online = live.filter((node) => node.online && !node.revoked).length;
  const attention = live.filter(needsAttention).length;
  const networks = new Set(live.map((node) => node.organisation_id)).size;
  // During an outage the counts are unknown, not zero.
  const unknown = inventory.errors.length > 0 && live.length === 0;
  const count = (value: number) => (unknown ? "–" : value);
  const errors = [...new Set([...blockedErrors, ...inventory.errors])];

  return (
    <>
      <dl className="stat-grid" aria-label="Device summary">
        <div>
          <dt>Devices</dt>
          <dd>{count(live.length)}</dd>
        </div>
        <div>
          <dt>Online</dt>
          <dd>{count(online)}</dd>
        </div>
        <div>
          <dt>Need attention</dt>
          <dd>{count(attention)}</dd>
        </div>
        <div>
          <dt>Networks</dt>
          <dd>{networks || ctx.organisations.length}</dd>
        </div>
      </dl>
      <Section
        id="inventory"
        title="All devices"
        description="Open a device's details to rename it, approve its routes or remove it."
      >
        {errors.map((error) => (
          <Alert tone="error" key={error} title="Some devices couldn't be listed">
            {error}
          </Alert>
        ))}
        <DeviceActions
          loadFailed={inventory.errors.length > 0}
          nodes={inventory.nodes}
          people={memberships.map((row) => ({
            userId: row.userId,
            email: row.email,
            name: row.name,
          }))}
        />
      </Section>
      <WgOnlyManager
        peers={unmanaged.peers}
        errors={unmanaged.errors}
        role={ctx.role}
        organisationId={ctx.organisationId}
      />
    </>
  );
}

function InventorySkeleton() {
  return (
    <>
      <div className="stat-grid" aria-hidden="true">
        {[0, 1, 2, 3].map((index) => (
          <div key={index}>
            <Skeleton lines={2} label="Loading summary" />
          </div>
        ))}
      </div>
      <Section id="inventory" title="All devices">
        <SkeletonTable rows={6} label="Loading devices" />
      </Section>
    </>
  );
}

export default async function DevicesPage() {
  const ctx = await requireConsoleContext();

  return (
    <ConsoleShell ctx={ctx} current="/devices">
      <div className="stack">
        <PageHeader
          eyebrow="Your network"
          title="Devices"
          description="Every machine you can reach through your linked network accounts. Changes stay scoped to the organisation that owns the device."
          actions={
            can(ctx.role, "manage_join_keys") ? (
              <Link className="button" href="/join-keys">
                Add a device
              </Link>
            ) : undefined
          }
        />
        <Suspense fallback={<InventorySkeleton />}>
          <DeviceInventory ctx={ctx} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}
