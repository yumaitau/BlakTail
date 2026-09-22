import { ConsoleShell } from "@/components/console-shell";
import { IdentitySettings } from "@/components/identity-settings";
import { ApiClientManager } from "@/components/api-client-manager";
import { InvitationManager } from "@/components/invitation-manager";
import { MembershipManager } from "@/components/membership-manager";
import { OidcProviderManager } from "@/components/oidc-provider-manager";
import { ScimManager } from "@/components/scim-manager";
import { PageHeader } from "@/components/page-header";
import { DnsSettings } from "@/components/dns-settings";
import { WebhookManager } from "@/components/webhook-manager";
import { getDns, listApiClients, listWebhooks } from "@/lib/coord";
import { listPendingInvitations } from "@/lib/invitations";
import { listIdentitySettings } from "@/lib/identity-links";
import { listIdentityProviders, listMemberships } from "@/lib/oidc";
import { canMutateTailnet, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";
import { TAGLINE } from "@/lib/tagline";

export default async function SettingsPage() {
  const ctx = await requireConsoleContext();
  const [invitations, identitySettings, apiClients, webhooks, providers, memberships, dns] =
    await Promise.all([
      listPendingInvitations(ctx),
      listIdentitySettings(ctx),
      ctx.role === "member"
        ? Promise.resolve([])
        : listApiClients(ctx).catch(() => []),
      canMutateTailnet(ctx.role)
        ? listWebhooks(ctx).catch(() => [])
        : Promise.resolve([]),
      ctx.role === "owner"
        ? listIdentityProviders(ctx.organisationId)
        : Promise.resolve([]),
      ctx.role === "owner"
        ? listMemberships(ctx.organisationId)
        : Promise.resolve([]),
      getDns(ctx).catch(() => null),
    ]);

  return (
    <ConsoleShell ctx={ctx} current="/settings">
      <div className="stack">
        <PageHeader
          title="Settings"
          description="One person, every explicitly linked network account, and independent ways to sign in."
        />
        <nav className="section-nav" aria-label="Settings sections">
          <a href="#account">Account</a>
          <a href="#identities">Identities</a>
          {ctx.role === "owner" ? <a href="#sso">Single sign-on</a> : null}
          {ctx.role === "owner" ? <a href="#scim">Directory</a> : null}
          {ctx.role === "owner" ? <a href="#members">Members</a> : null}
          <a href="#dns">DNS</a>
          {canMutateTailnet(ctx.role) ? <a href="#webhooks">Webhooks</a> : null}
          {ctx.role === "owner" ? <a href="#automation">Automation</a> : null}
          {ctx.role === "owner" ? <a href="#invitations">Invitations</a> : null}
        </nav>
        <div className="panel stack" id="account">
          <p>
            <strong>Signed in as:</strong> {ctx.name} ({ctx.email})
          </p>
          <p>
            <strong>Role:</strong> {roleLabel(ctx.role)}
          </p>
          <p>
            <strong>Organisation:</strong>{" "}
            <span className="badge network">{ctx.organisationName}</span>
          </p>
          <p>
            <strong>Accessible workspaces:</strong> {ctx.organisations.length}
          </p>
          <p>
            <strong>Coordinator org id:</strong>{" "}
            <span className="mono">{ctx.coordOrgId}</span>
          </p>
          <p className="region-mark">
            <span className="region-dot" aria-hidden="true" />
            <strong>Onshore</strong>
            <span>Sydney, Australia · AU · ap-southeast-2</span>
          </p>
          <p className="tagline">{TAGLINE}</p>
          <p className="muted">
            No analytics leave the building. Fonts are local. Auth lives in
            onshore Postgres. Tailnet authority stays with the Rust
            coordinator. Switching workspaces never signs you out of another
            one.
          </p>
        </div>
        <div id="identities">
          <IdentitySettings
            identities={identitySettings.identities}
            networkAccounts={identitySettings.networkAccounts}
            conflicts={identitySettings.conflicts}
          />
        </div>
        {ctx.role === "owner" ? (
          <div id="sso" className="stack">
            <OidcProviderManager providers={providers} />
            <div id="scim">
              <ScimManager />
            </div>
          </div>
        ) : null}
        {ctx.role === "owner" ? (
          <div id="members">
            <MembershipManager memberships={memberships} />
          </div>
        ) : null}
        {dns ? (
          <div id="dns">
            <DnsSettings initial={dns} readOnly={ctx.role === "member"} />
          </div>
        ) : (
          <div className="panel stack" id="dns">
            <h2>Organisation DNS</h2>
            <p className="muted">
              Coordinator DNS settings are unavailable in this environment.
            </p>
          </div>
        )}
        {canMutateTailnet(ctx.role) ? (
          <div id="webhooks">
            <WebhookManager destinations={webhooks} />
          </div>
        ) : null}
        {ctx.role === "owner" ? (
          <div id="automation">
            <ApiClientManager clients={apiClients} />
          </div>
        ) : null}
        {ctx.role === "owner" ? (
          <div id="invitations">
            <InvitationManager
              invitations={invitations.map((invitation) => ({
                id: invitation.id,
                email: invitation.email,
                role: invitation.role,
                expiresAt: invitation.expiresAt.toISOString(),
              }))}
            />
          </div>
        ) : null}
      </div>
    </ConsoleShell>
  );
}
