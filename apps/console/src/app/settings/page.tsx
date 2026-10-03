import Link from "next/link";
import { ConsoleShell } from "@/components/console-shell";
import { IdentitySettings } from "@/components/identity-settings";
import { ApiClientManager } from "@/components/api-client-manager";
import { InvitationManager } from "@/components/invitation-manager";
import { MembershipManager } from "@/components/membership-manager";
import { OidcProviderManager } from "@/components/oidc-provider-manager";
import { ScimManager } from "@/components/scim-manager";
import { PageHeader } from "@/components/page-header";
import { WebhookManager } from "@/components/webhook-manager";
import { listApiClients, listWebhooks } from "@/lib/coord";
import { listEventCatalogue } from "@/lib/coord-events";
import { listPendingInvitations } from "@/lib/invitations";
import { listIdentitySettings } from "@/lib/identity-links";
import { listIdentityProviders, listMemberships } from "@/lib/oidc";
import { AccountSecurity } from "@/components/account-security";
import { SignInSecurity } from "@/components/sign-in-security";
import { getSignInPolicy, identityAssurance, listDomains } from "@/lib/auth-policy";
import { MFA_PRIVILEGED_ROLES } from "@/lib/auth-policy-core";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext } from "@/lib/session";
import { TAGLINE } from "@/lib/tagline";

export default async function SettingsPage() {
  const ctx = await requireConsoleContext();
  const canSecurity = can(ctx.role, "manage_security");
  const canApiClients = can(ctx.role, "manage_api_clients");
  const canIntegrations = can(ctx.role, "manage_integrations");
  const [
    invitations,
    identitySettings,
    apiClients,
    webhooks,
    catalogue,
    providers,
    memberships,
    signInPolicy,
    domains,
    assurance,
  ] = await Promise.all([
    listPendingInvitations(ctx),
    listIdentitySettings(ctx),
    canApiClients ? listApiClients(ctx).catch(() => []) : Promise.resolve([]),
    canIntegrations ? listWebhooks(ctx).catch(() => []) : Promise.resolve([]),
    canIntegrations ? listEventCatalogue(ctx).catch(() => []) : Promise.resolve([]),
    canSecurity
      ? listIdentityProviders(ctx.organisationId)
      : Promise.resolve([]),
    canSecurity
      ? listMemberships(ctx.organisationId)
      : Promise.resolve([]),
    getSignInPolicy(ctx.organisationId),
    canSecurity ? listDomains(ctx.organisationId) : Promise.resolve([]),
    identityAssurance(ctx.userId),
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
          <a href="#account-security">Account security</a>
          {canSecurity ? <a href="#sign-in-policy">Sign-in policy</a> : null}
          {canSecurity ? <a href="#sso">Single sign-on</a> : null}
          {canSecurity ? <a href="#scim">Directory</a> : null}
          {canSecurity ? <a href="#members">Members</a> : null}
          <a href="#dns">DNS</a>
          {canIntegrations ? <a href="#webhooks">Webhooks</a> : null}
          {canApiClients ? <a href="#automation">Automation</a> : null}
          {canSecurity ? <a href="#invitations">Invitations</a> : null}
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
        <div id="account-security">
          <AccountSecurity
            hasPassword={assurance.hasPassword}
            twoFactorEnabled={assurance.twoFactorEnabled}
            requiredByPolicy={
              signInPolicy.requireMfaForPrivileged &&
              MFA_PRIVILEGED_ROLES.includes(ctx.role)
            }
          />
        </div>
        {canSecurity ? (
          <div id="sign-in-policy">
            <SignInSecurity
              organisationName={ctx.organisationName}
              policy={signInPolicy}
              domains={domains}
              denied={permissionReason(ctx.role, "manage_security")}
            />
          </div>
        ) : null}
        {canSecurity ? (
          <div id="sso" className="stack">
            <OidcProviderManager providers={providers} />
            <div id="scim">
              <ScimManager />
            </div>
          </div>
        ) : null}
        {canSecurity ? (
          <div id="members">
            <MembershipManager
              memberships={memberships}
              actorRole={ctx.role}
              organisationName={ctx.organisationName}
            />
          </div>
        ) : null}
        <div className="panel stack" id="dns">
          <h2>Organisation DNS</h2>
          <p className="muted">
            Nameserver groups, custom zones, split DNS, previews and revision
            history now live on their own page.
          </p>
          <div>
            <Link className="button secondary" href="/dns">
              Open DNS
            </Link>
          </div>
        </div>
        {canIntegrations ? (
          <div id="webhooks">
            <WebhookManager destinations={webhooks} catalogue={catalogue} />
          </div>
        ) : null}
        {canApiClients ? (
          <div id="automation">
            <ApiClientManager clients={apiClients} />
          </div>
        ) : null}
        {canSecurity ? (
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
