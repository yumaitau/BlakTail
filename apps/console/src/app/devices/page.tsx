import { ConsoleShell } from "@/components/console-shell";
import { DeviceActions } from "@/components/device-actions";
import { PageHeader } from "@/components/page-header";
import { PathMotif } from "@/components/path-motif";
import { WgOnlyManager } from "@/components/wg-only-manager";
import { listAllNodes, listAllWgOnlyPeers, type NetworkNode } from "@/lib/coord";
import { listMemberships } from "@/lib/oidc";
import { requireConsoleContext } from "@/lib/session";

function needsAttention(node: NetworkNode): boolean {
  return (
    !node.deleted &&
    (node.revoked ||
      node.expired ||
      node.expires_soon ||
      node.advertised_routes.some((route) => !node.approved_routes.includes(route)))
  );
}

export default async function DevicesPage() {
  const ctx = await requireConsoleContext();
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

  return (
    <ConsoleShell ctx={ctx} current="/devices">
      <div className="stack">
        <PageHeader
          eyebrow="Your network"
          title="Devices"
          description="Every machine you can reach through your linked network accounts. Changes stay scoped to the organisation that owns the device."
        />
        <section className="overview" aria-label="Device summary">
          <div className="panel overview-copy">
            <p className="eyebrow">Connected places</p>
            <div className="overview-stats">
              <div className="overview-stat">
                <strong>{live.length}</strong>
                <span>Devices</span>
              </div>
              <div className="overview-stat">
                <strong>{online}</strong>
                <span>Online</span>
              </div>
              <div className="overview-stat">
                <strong>{attention}</strong>
                <span>Needs attention</span>
              </div>
              <div className="overview-stat">
                <strong>{networks || ctx.organisations.length}</strong>
                <span>Networks</span>
              </div>
            </div>
          </div>
          <div className="overview-path" aria-hidden="true">
            <PathMotif />
          </div>
        </section>
        <div className="panel table-panel">
          {[...blockedErrors, ...inventory.errors].map((error) => (
            <p className="error" key={error}>
              {error}
            </p>
          ))}
          <DeviceActions
            nodes={inventory.nodes}
            people={memberships.map((row) => ({
              userId: row.userId,
              email: row.email,
              name: row.name,
            }))}
          />
        </div>
        <WgOnlyManager
          peers={unmanaged.peers}
          errors={unmanaged.errors}
          role={ctx.role}
          organisationId={ctx.organisationId}
        />
      </div>
    </ConsoleShell>
  );
}
