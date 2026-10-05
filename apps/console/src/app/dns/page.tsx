import { Suspense } from "react";
import { errorText } from "@/lib/server-errors";
import { ConsoleShell } from "@/components/console-shell";
import { PageHeader } from "@/components/page-header";
import { DnsEditor } from "@/components/dns/dns-editor";
import { DnsPreviewPanel } from "@/components/dns/dns-preview";
import { DnsRevisions } from "@/components/dns/dns-revisions";
import { Alert } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { MonoValue } from "@/components/ui/mono-value";
import { PermissionNotice } from "@/components/ui/permission-notice";
import { Section } from "@/components/ui/section";
import { Skeleton } from "@/components/ui/skeleton";
import { getDns, listNodes, type OrgDnsResponse } from "@/lib/coord";
import { listDnsRevisions, type DnsRevision } from "@/lib/coord-dns";
import { permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

export default async function DnsPage() {
  const ctx = await requireConsoleContext();
  const readOnlyReason = permissionReason(ctx.role, "manage_dns");

  return (
    <ConsoleShell ctx={ctx} current="/dns">
      <div className="stack">
        <PageHeader
          eyebrow={ctx.organisationName}
          title="DNS"
          description="Nameserver groups, custom zones and split DNS for this organisation. MagicDNS device names stay coordinator-authoritative and are never forwarded."
        />
        <nav className="section-nav" aria-label="DNS sections">
          <a href="#overview">Overview</a>
          <a href="#nameserver-groups">Nameserver groups</a>
          <a href="#zones">Custom zones</a>
          <a href="#legacy">Split and search</a>
          <a href="#publish">Publish</a>
          <a href="#preview">Preview</a>
          <a href="#revisions">History</a>
        </nav>
        {readOnlyReason ? <PermissionNotice reason={readOnlyReason} /> : null}
        <Suspense
          fallback={
            <>
              <Section title="Effective settings">
                <Skeleton lines={4} label="Loading DNS settings" />
              </Section>
              <Section title="Nameserver groups">
                <Skeleton lines={3} label="Loading nameserver groups" />
              </Section>
            </>
          }
        >
          <DnsWorkspace ctx={ctx} readOnlyReason={readOnlyReason} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}

async function DnsWorkspace({
  ctx,
  readOnlyReason,
}: {
  ctx: ConsoleContext;
  readOnlyReason: string | null;
}) {
  let dns: OrgDnsResponse | null = null;
  let dnsError: string | null = null;
  try {
    dns = await getDns(ctx);
  } catch (error) {
    dnsError = errorText(error, "Could not load organisation DNS.");
  }
  if (!dns) {
    return (
      <Alert tone="error" title="Organisation DNS couldn't be loaded">
        {dnsError} Check that the coordinator is reachable, then reload this page.
      </Alert>
    );
  }
  let revisions: DnsRevision[] = [];
  let revisionsError: string | null = null;
  const [revisionResult, nodes] = await Promise.all([
    listDnsRevisions(ctx).then(
      (value) => ({ ok: true as const, value }),
      (error: unknown) => ({ ok: false as const, error }),
    ),
    listNodes(ctx).catch(() => []),
  ]);
  if (revisionResult.ok) revisions = revisionResult.value;
  else revisionsError = errorText(revisionResult.error, "Could not load revision history.");
  const devices = nodes
    .filter((node) => !node.revoked && !node.deleted)
    .map((node) => ({
      id: node.id,
      label: `${node.display_name || node.name}${
        node.tags.length > 0 ? ` (${node.tags.join(", ")})` : ""
      }`,
    }));
  const groups = dns.dns.nameserver_groups ?? [];
  const zones = dns.dns.zones ?? [];
  const warnings = dns.warnings ?? [];

  return (
    <>
      <Section
        id="overview"
        title="Effective settings"
        description={`Published revision ${dns.revision}${
          typeof dns.enrolled === "number"
            ? ` · ${dns.applied ?? 0} of ${dns.enrolled} enrolled devices on this revision`
            : ""
        }.`}
        actions={
          dns.dns.managed === false ? (
            <Badge tone="muted">Not managed</Badge>
          ) : (
            <Badge tone="success">Managed</Badge>
          )
        }
      >
        <dl className="details">
          <div>
            <dt>Managed</dt>
            <dd>
              {dns.dns.managed === false
                ? "No: agents leave device DNS alone apart from MagicDNS"
                : "Yes: agents apply these settings"}
            </dd>
          </div>
          <div>
            <dt>MagicDNS suffix</dt>
            <dd>
              <span className="row">
                <MonoValue value={dns.magic_dns_suffix} copy copyLabel="Copy MagicDNS suffix" />
                <Badge tone="brand">Protected</Badge>
              </span>
            </dd>
          </div>
          <div>
            <dt>Nameserver groups</dt>
            <dd>
              {groups.length === 0
                ? "None"
                : groups
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
              {zones.length === 0
                ? "None"
                : zones
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
        {warnings.length > 0 ? (
          <Alert
            tone="warning"
            title={`${warnings.length} warning${warnings.length === 1 ? "" : "s"} on the published revision`}
          >
            <ul className="audit-details" aria-label="DNS warnings">
              {warnings.map((warning) => (
                <li key={warning}>{warning}</li>
              ))}
            </ul>
          </Alert>
        ) : (
          <p className="muted small">No warnings for the published revision.</p>
        )}
      </Section>
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
  );
}
