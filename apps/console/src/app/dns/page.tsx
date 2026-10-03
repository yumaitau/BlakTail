import { ConsoleShell } from "@/components/console-shell";
import { PageHeader } from "@/components/page-header";
import { DnsEditor } from "@/components/dns/dns-editor";
import { DnsPreviewPanel } from "@/components/dns/dns-preview";
import { DnsRevisions } from "@/components/dns/dns-revisions";
import { getDns, listNodes, type OrgDnsResponse } from "@/lib/coord";
import { listDnsRevisions, type DnsRevision } from "@/lib/coord-dns";
import { permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";

function message(error: unknown, fallback: string): string {
  return error instanceof Error ? error.message : fallback;
}

export default async function DnsPage() {
  const ctx = await requireConsoleContext();
  let dns: OrgDnsResponse | null = null;
  let dnsError: string | null = null;
  try {
    dns = await getDns(ctx);
  } catch (error) {
    dnsError = message(error, "Could not load organisation DNS.");
  }
  let revisions: DnsRevision[] = [];
  let revisionsError: string | null = null;
  try {
    revisions = dns ? await listDnsRevisions(ctx) : [];
  } catch (error) {
    revisionsError = message(error, "Could not load revision history.");
  }
  const nodes = await listNodes(ctx).catch(() => []);
  const devices = nodes
    .filter((node) => !node.revoked && !node.deleted)
    .map((node) => ({
      id: node.id,
      label: `${node.display_name || node.name}${
        node.tags.length > 0 ? ` (${node.tags.join(", ")})` : ""
      }`,
    }));
  const readOnlyReason = permissionReason(ctx.role, "manage_dns");

  return (
    <ConsoleShell ctx={ctx} current="/dns">
      <div className="stack">
        <PageHeader
          eyebrow="DNS"
          title="DNS"
          description="Nameserver groups, custom zones and split DNS for this organisation. MagicDNS device names stay coordinator-authoritative and are never forwarded."
        />
        <nav className="section-nav" aria-label="DNS sections">
          <a href="#overview">Overview</a>
          <a href="#nameserver-groups">Nameserver groups</a>
          <a href="#zones">Custom zones</a>
          <a href="#legacy">Split and search</a>
          <a href="#preview">Preview</a>
          <a href="#revisions">History</a>
        </nav>
        {dns ? (
          <>
            <div className="panel stack" id="overview">
              <h2>Effective settings</h2>
              <dl className="details">
                <div>
                  <dt>Published revision</dt>
                  <dd>
                    {dns.revision}
                    {typeof dns.enrolled === "number"
                      ? ` · ${dns.applied ?? 0} of ${dns.enrolled} enrolled devices on this revision`
                      : ""}
                  </dd>
                </div>
                <div>
                  <dt>Managed</dt>
                  <dd>
                    {dns.dns.managed === false
                      ? "No: agents leave device DNS alone apart from MagicDNS"
                      : "Yes"}
                  </dd>
                </div>
                <div>
                  <dt>MagicDNS suffix</dt>
                  <dd>
                    <span className="mono">{dns.magic_dns_suffix}</span>{" "}
                    <span className="badge network">Protected</span>
                  </dd>
                </div>
                <div>
                  <dt>Nameserver groups</dt>
                  <dd>
                    {(dns.dns.nameserver_groups ?? []).length === 0
                      ? "None"
                      : (dns.dns.nameserver_groups ?? [])
                          .map(
                            (group) =>
                              `${group.name}${group.enabled === false ? " (disabled)" : ""} → ${
                                group.all_devices ? "all devices" : (group.tags ?? []).join(", ")
                              }`,
                          )
                          .join("; ")}
                  </dd>
                </div>
                <div>
                  <dt>Custom zones</dt>
                  <dd>
                    {(dns.dns.zones ?? []).length === 0
                      ? "None"
                      : (dns.dns.zones ?? [])
                          .map(
                            (zone) =>
                              `${zone.name} (${zone.records?.length ?? 0} records${
                                zone.enabled === false ? ", disabled" : ""
                              })`,
                          )
                          .join("; ")}
                  </dd>
                </div>
                <div>
                  <dt>Split routes · search domains</dt>
                  <dd>
                    {dns.dns.split.length} · {dns.dns.search_domains.length}
                  </dd>
                </div>
              </dl>
              {(dns.warnings ?? []).length > 0 ? (
                <ul aria-label="DNS warnings">
                  {(dns.warnings ?? []).map((warning) => (
                    <li key={warning}>
                      <span className="badge pending">Warning</span> {warning}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="muted">No warnings for the published revision.</p>
              )}
            </div>
            <DnsEditor
              key={dns.etag}
              initial={dns.dns}
              etag={dns.etag}
              organisationName={ctx.organisationName}
              roleLabel={roleLabel(ctx.role).toLowerCase()}
              readOnlyReason={readOnlyReason}
            />
            <DnsPreviewPanel devices={devices} />
            <DnsRevisions
              revisions={revisions}
              loadError={revisionsError}
              current={dns.dns}
              etag={dns.etag}
              hasPrevious={dns.has_previous}
              readOnlyReason={readOnlyReason}
            />
          </>
        ) : (
          <div className="panel stack" id="overview">
            <h2>Organisation DNS unavailable</h2>
            <p className="error">{dnsError}</p>
            <p className="muted">
              Check that the coordinator is reachable, then reload this page.
            </p>
          </div>
        )}
      </div>
    </ConsoleShell>
  );
}
