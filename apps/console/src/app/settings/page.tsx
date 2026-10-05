import Link from "next/link";
import { Suspense } from "react";
import { ConsoleShell } from "@/components/console-shell";
import { IdentitySettings } from "@/components/identity-settings";
import { ApiClientManager } from "@/components/api-client-manager";
import { InvitationManager } from "@/components/invitation-manager";
import { MembershipManager } from "@/components/membership-manager";
import { OidcProviderManager } from "@/components/oidc-provider-manager";
import { ScimManager } from "@/components/scim-manager";
import { DirectoryRoleMapping } from "@/components/directory-role-mapping";
import { SettingsNav, type SettingsNavGroup } from "@/components/settings-nav";
import { WebhookManager } from "@/components/webhook-manager";
import { NotificationChannels } from "@/components/notification-channels";
import { AccountSecurity } from "@/components/account-security";
import { ChangePassword } from "@/components/change-password";
import { SignInSecurity } from "@/components/sign-in-security";
import { Alert, Badge, PageHeader, Section, SkeletonTable } from "@/components/ui";
import { getDirectorySettings, listGroupMappings } from "@/lib/directory-mapping";
import { DEFAULT_DIRECTORY_SETTINGS } from "@/lib/directory-mapping-core";
import { listApiClients, listWebhooks, type ApiClient, type WebhookDestination } from "@/lib/coord";
import { listEventCatalogue, type EventKind } from "@/lib/coord-events";
import {
  getNotificationCapabilities,
  type NotificationCapabilities,
} from "@/lib/coord-notifications";
import { listPendingInvitations } from "@/lib/invitations";
import { listIdentitySettings } from "@/lib/identity-links";
import { listIdentityProviders, listMemberships } from "@/lib/oidc";
import { getSignInPolicy, identityAssurance, listDomains } from "@/lib/auth-policy";
import { MFA_PRIVILEGED_ROLES } from "@/lib/auth-policy-core";
import { errorText } from "@/lib/server-errors";
import { can, permissionReason, roleLabel } from "@/lib/roles";
import { requireConsoleContext, type ConsoleContext } from "@/lib/session";

/** Coordinator-backed lists: a failed load is reported, never shown as empty. */
async function loadOr<T>(
  enabled: boolean,
  load: () => Promise<T>,
  empty: T,
  fallback: string,
): Promise<{ data: T; error: string | null }> {
  if (!enabled) return { data: empty, error: null };
  try {
    return { data: await load(), error: null };
  } catch (error) {
    return { data: empty, error: errorText(error, fallback) };
  }
}

function navGroups(ctx: ConsoleContext, hasConflicts: boolean): SettingsNavGroup[] {
  const owner = can(ctx.role, "manage_security");
  const integrations = can(ctx.role, "manage_integrations");
  const groups: SettingsNavGroup[] = [
    {
      label: "Your account",
      items: [
        { id: "account", label: "Profile" },
        { id: "identities", label: "Ways to sign in" },
        ...(hasConflicts ? [{ id: "role-conflicts", label: "Owner role decisions" }] : []),
        { id: "account-security", label: "Password and two-step" },
      ],
    },
    {
      label: "Organisation",
      items: [
        { id: "dns", label: "DNS" },
        ...(integrations
          ? [
              { id: "notifications", label: "Notification channels" },
              { id: "webhooks", label: "Webhooks" },
            ]
          : []),
        ...(owner ? [] : [{ id: "owner-only", label: "Owner-only settings" }]),
      ],
    },
  ];
  if (owner) {
    groups.push({
      label: "Owners only",
      items: [
        { id: "members", label: "Members and roles" },
        { id: "invitations", label: "Invitations" },
        { id: "sign-in-policy", label: "Sign-in policy and domains" },
        { id: "sso", label: "Single sign-on" },
        { id: "scim", label: "Directory provisioning" },
        { id: "directory-roles", label: "Directory group roles" },
        { id: "automation", label: "API clients" },
      ],
    });
  }
  return groups;
}

export default async function SettingsPage() {
  const ctx = await requireConsoleContext();
  return (
    <ConsoleShell ctx={ctx} current="/settings">
      <div className="stack">
        <PageHeader
          title="Settings"
          description={`Your own account, and how ${ctx.organisationName} signs people in, provisions them and sends events to other systems.`}
        />
        <Suspense fallback={<SettingsSkeleton />}>
          <SettingsContent ctx={ctx} />
        </Suspense>
      </div>
    </ConsoleShell>
  );
}

function SettingsSkeleton() {
  return (
    <div className="settings-layout">
      <div aria-hidden="true" />
      <div className="settings-content">
        <div className="panel">
          <SkeletonTable rows={4} label="Loading settings" />
        </div>
        <div className="panel">
          <SkeletonTable rows={3} label="Loading settings" />
        </div>
      </div>
    </div>
  );
}

async function SettingsContent({ ctx }: { ctx: ConsoleContext }) {
  const owner = can(ctx.role, "manage_security");
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
    notificationCapabilities,
    directorySettings,
    groupMappings,
  ] = await Promise.all([
    owner ? listPendingInvitations(ctx) : Promise.resolve([]),
    listIdentitySettings(ctx),
    loadOr<ApiClient[]>(canApiClients, () => listApiClients(ctx), [], "Could not load API clients."),
    loadOr<WebhookDestination[]>(
      canIntegrations,
      () => listWebhooks(ctx),
      [],
      "Could not load webhooks and notification channels.",
    ),
    loadOr<EventKind[]>(canIntegrations, () => listEventCatalogue(ctx), [], "Could not load the event catalogue."),
    owner ? listIdentityProviders(ctx.organisationId) : Promise.resolve([]),
    owner ? listMemberships(ctx.organisationId) : Promise.resolve([]),
    getSignInPolicy(ctx.organisationId),
    owner ? listDomains(ctx.organisationId) : Promise.resolve([]),
    identityAssurance(ctx.userId),
    loadOr<NotificationCapabilities | null>(
      canIntegrations,
      () => getNotificationCapabilities(ctx),
      null,
      "Could not load channel settings.",
    ),
    owner ? getDirectorySettings(ctx.organisationId) : Promise.resolve(DEFAULT_DIRECTORY_SETTINGS),
    owner ? listGroupMappings(ctx.organisationId) : Promise.resolve([]),
  ]);
  const destinations = webhooks.data;
  const plainWebhooks = destinations.filter((destination) => (destination.kind ?? "webhook") === "webhook");
  const channels = destinations.filter((destination) => (destination.kind ?? "webhook") !== "webhook");
  const ownerReason = permissionReason(ctx.role, "manage_security");

  return (
    <div className="settings-layout">
      <SettingsNav groups={navGroups(ctx, identitySettings.conflicts.length > 0)} />
      <div className="settings-content">
        <div className="settings-group" aria-labelledby="group-account">
          <div className="settings-group-head">
            <h2 id="group-account">Your account</h2>
            <p className="muted">
              Only you see these. They follow you across every organisation you belong to.
            </p>
          </div>
          <Section
            id="account"
            headingLevel={3}
            title="Profile"
            description="Who you're signed in as, and the organisation you're working in now."
          >
            <dl className="detail-list">
              <dt>Name</dt>
              <dd>{ctx.name}</dd>
              <dt>Email</dt>
              <dd>{ctx.email}</dd>
              <dt>Organisation</dt>
              <dd>
                <Badge tone="brand">{ctx.organisationName}</Badge>
              </dd>
              <dt>Your role here</dt>
              <dd>{roleLabel(ctx.role)}</dd>
              <dt>Organisations you can open</dt>
              <dd>{ctx.organisations.length}</dd>
              <dt>Coordinator organisation ID</dt>
              <dd className="mono">{ctx.coordOrgId}</dd>
              <dt>Data location</dt>
              <dd>
                <span className="region-mark">
                  <span className="region-dot" aria-hidden="true" />
                  <strong>Onshore</strong>
                  <span>Sydney, Australia · ap-southeast-2</span>
                </span>
              </dd>
            </dl>
            <p className="muted">
              No analytics leave the building and fonts are served locally. Sign-in records live
              in onshore Postgres; the coordinator holds network state. Switching organisations
              never signs you out of another one.
            </p>
          </Section>
          <IdentitySettings
            identities={identitySettings.identities}
            networkAccounts={identitySettings.networkAccounts}
            conflicts={identitySettings.conflicts}
          />
          <div id="account-security" className="settings-group">
            {assurance.hasPassword ? <ChangePassword /> : null}
            <AccountSecurity
              hasPassword={assurance.hasPassword}
              twoFactorEnabled={assurance.twoFactorEnabled}
              requiredByPolicy={
                signInPolicy.requireMfaForPrivileged && MFA_PRIVILEGED_ROLES.includes(ctx.role)
              }
            />
          </div>
        </div>

        <div className="settings-group" aria-labelledby="group-organisation">
          <div className="settings-group-head">
            <h2 id="group-organisation">{ctx.organisationName}</h2>
            <p className="muted">
              Shared settings for this organisation. Every change is recorded in the audit log.
            </p>
          </div>
          <Section
            id="dns"
            headingLevel={3}
            title="Organisation DNS"
            description="Nameserver groups, custom zones, split DNS, previews and revision history have their own page."
            actions={
              <Link className="button secondary ui-button" href="/dns">
                Open DNS
              </Link>
            }
          />
          {canIntegrations ? (
            <>
              <NotificationChannels
                channels={channels}
                catalogue={catalogue.data}
                capabilities={notificationCapabilities.data}
                loadError={webhooks.error ?? notificationCapabilities.error}
                canAcknowledgeResidency={owner}
                organisationName={ctx.organisationName}
                roleLabel={roleLabel(ctx.role)}
              />
              <WebhookManager
                destinations={plainWebhooks}
                catalogue={catalogue.data}
                loadError={webhooks.error}
                catalogueError={catalogue.error}
              />
            </>
          ) : null}
          {!owner ? (
            <Section
              id="owner-only"
              headingLevel={3}
              title="Owner-only settings"
              description="Members and roles, invitations, the sign-in policy, single sign-on, directory provisioning and API clients are managed by owners."
            >
              <Alert tone="info" title="Why you can't see these">
                <p>{ownerReason}</p>
                {canIntegrations ? null : (
                  <p>
                    Notification channels and webhooks are hidden too.{" "}
                    {permissionReason(ctx.role, "manage_integrations")}
                  </p>
                )}
                <p>Ask an owner of {ctx.organisationName} if something here needs to change.</p>
              </Alert>
            </Section>
          ) : null}
        </div>

        {owner ? (
          <div className="settings-group" aria-labelledby="group-owner">
            <div className="settings-group-head">
              <h2 id="group-owner">
                Owner settings <Badge tone="warning">Owners only</Badge>
              </h2>
              <p className="muted">
                People, sign-in and automation for {ctx.organisationName}. Your organisation can
                require a recent sign-in before these change.
              </p>
            </div>
            <MembershipManager
              memberships={memberships}
              actorRole={ctx.role}
              organisationName={ctx.organisationName}
            />
            <InvitationManager
              invitations={invitations.map((invitation) => ({
                id: invitation.id,
                email: invitation.email,
                role: invitation.role,
                expiresAt: invitation.expiresAt.toISOString(),
              }))}
            />
            <SignInSecurity
              organisationName={ctx.organisationName}
              policy={signInPolicy}
              domains={domains}
              denied={ownerReason}
            />
            <OidcProviderManager providers={providers} />
            <ScimManager />
            <DirectoryRoleMapping
              settings={directorySettings}
              mappings={groupMappings}
              organisationName={ctx.organisationName}
            />
            {canApiClients ? (
              <ApiClientManager clients={apiClients.data} loadError={apiClients.error} />
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}
