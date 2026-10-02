import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { auth, type Session } from "./auth";
import { requireBootstrapLocked } from "./bootstrap-state";
import { rawSqlClient } from "./db/client";
import { resolveOrganisationRole, type OrgRole } from "./roles";

export type { OrgRole } from "./roles";
export { can, roleLabel } from "./roles";

export const ACTIVE_ORGANISATION_COOKIE = "blaktail.active_organisation";
export const ORGANISATION_COOKIE = ACTIVE_ORGANISATION_COOKIE;

export const activeOrganisationCookieOptions = {
  httpOnly: true,
  sameSite: "lax" as const,
  secure: process.env.NODE_ENV === "production",
  path: "/",
  maxAge: 60 * 60 * 24 * 365,
};

export type OrganisationAccess = {
  organisationId: string;
  organisationName: string;
  coordOrgId: string;
  role: OrgRole;
  membershipIds: string[];
  networkAccountIds: string[];
  networkAccountNames: string[];
  identityUserIds: string[];
};

export type OrganisationContext = OrganisationAccess;

export type BlockedOrganisation = {
  organisationId: string;
  organisationName: string;
  reason: "role_conflict";
};

export type PersonSessionContext = {
  personId: string;
  userId: string;
  sessionId: string;
  email: string;
  name: string;
  identityName: string;
  sessionExpiresAt: Date;
  /** When this session was created by a sign-in. Drives step-up checks. */
  sessionCreatedAt: Date;
  organisations: OrganisationAccess[];
  blockedOrganisations: BlockedOrganisation[];
};

export type ConsoleContext = PersonSessionContext &
  OrganisationAccess & {
    networkAccountId: string;
    networkAccountName: string;
  };

type AccessRow = {
  membership_id: string;
  network_account_id: string;
  network_account_name: string;
  identity_user_id: string;
  organisation_id: string;
  organisation_name: string;
  coord_org_id: string;
  role: OrgRole;
  effective_role: OrgRole | null;
  membership_signature: string | null;
};

export class OrganisationAccessError extends Error {}

/** Resolve the live linked-identity and membership graph on every request. */
export async function resolveSessionContext(
  session: Session,
): Promise<PersonSessionContext> {
  await requireBootstrapLocked();
  const sessionExpiresAt = new Date(session.session.expiresAt);
  if (sessionExpiresAt.getTime() <= Date.now()) {
    throw new OrganisationAccessError("Session has expired.");
  }

  const sql = rawSqlClient();
  const [identity] = await sql`
    SELECT pli.person_id, p.display_name
    FROM person_login_identity pli
    JOIN person p ON p.id = pli.person_id
    WHERE pli.user_id = ${session.user.id} AND pli.status = 'active'
    LIMIT 1
  `;
  if (!identity) {
    throw new OrganisationAccessError(
      "This sign-in identity is suspended or requires account recovery.",
    );
  }

  const rows = (await sql`
    SELECT m.id AS membership_id, na.id AS network_account_id,
      na.name AS network_account_name, pli.user_id AS identity_user_id,
      o.id AS organisation_id, o.name AS organisation_name,
      o.coord_org_id, m.role, mrr.effective_role,
      mrr.membership_signature
    FROM person_login_identity pli
    JOIN membership m ON m.user_id = pli.user_id
      AND coalesce(m.status, 'active') = 'active'
    JOIN network_account na ON na.membership_id = m.id
      AND na.login_identity_user_id = pli.user_id
      AND na.organisation_id = m.organisation_id
      AND na.status = 'active'
    JOIN organisation o ON o.id = m.organisation_id
    LEFT JOIN membership_role_resolution mrr
      ON mrr.person_id = pli.person_id
      AND mrr.organisation_id = m.organisation_id
    WHERE pli.person_id = ${identity.person_id}
      AND pli.status = 'active'
    ORDER BY o.name, o.id, m.id
  `) as unknown as AccessRow[];

  if (rows.length === 0) {
    throw new OrganisationAccessError(
      "Your account is signed in, but it has no active network accounts.",
    );
  }

  const grouped = new Map<string, AccessRow[]>();
  for (const row of rows) {
    const group = grouped.get(row.organisation_id) ?? [];
    group.push(row);
    grouped.set(row.organisation_id, group);
  }

  const organisations: OrganisationAccess[] = [];
  const blockedOrganisations: BlockedOrganisation[] = [];
  for (const group of grouped.values()) {
    const first = group[0]!;
    const role = resolveOrganisationRole(
      group.map((row) => ({
        organisationId: row.organisation_id,
        membershipId: row.membership_id,
        role: row.role,
        effectiveRole: row.effective_role,
        membershipSignature: row.membership_signature,
      })),
      first.organisation_id,
    );
    if (role === null || role === "blocked") {
      blockedOrganisations.push({
        organisationId: first.organisation_id,
        organisationName: first.organisation_name,
        reason: "role_conflict",
      });
      continue;
    }
    organisations.push({
      organisationId: first.organisation_id,
      organisationName: first.organisation_name,
      coordOrgId: first.coord_org_id,
      role,
      membershipIds: group.map((row) => row.membership_id),
      networkAccountIds: group.map((row) => row.network_account_id),
      networkAccountNames: group.map((row) => row.network_account_name),
      identityUserIds: [...new Set(group.map((row) => row.identity_user_id))],
    });
  }

  if (organisations.length === 0) {
    throw new OrganisationAccessError(
      "Every network account requires an audited owner role-conflict decision.",
    );
  }

  return {
    personId: identity.person_id,
    userId: session.user.id,
    sessionId: session.session.id,
    email: session.user.email,
    name: identity.display_name,
    identityName: session.user.name,
    sessionExpiresAt,
    sessionCreatedAt: new Date(session.session.createdAt),
    organisations,
    blockedOrganisations,
  };
}

export async function requireSession() {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) redirect("/sign-in");
  return session;
}

export async function requirePersonSessionContext(): Promise<PersonSessionContext> {
  return resolveSessionContext(await requireSession());
}

export function organisationContext(
  person: PersonSessionContext,
  organisationId: string,
): ConsoleContext {
  const organisation = person.organisations.find(
    (candidate) => candidate.organisationId === organisationId,
  );
  if (!organisation) {
    throw new OrganisationAccessError(
      "That network account is no longer accessible.",
    );
  }
  return {
    ...person,
    ...organisation,
    networkAccountId: organisation.networkAccountIds[0]!,
    networkAccountName:
      organisation.networkAccountNames[0] ?? organisation.organisationName,
  };
}

export function contextForOrganisation(
  ctx: PersonSessionContext,
  organisationId: string,
): ConsoleContext {
  return organisationContext(ctx, organisationId);
}

export async function consoleContextFromSession(
  session: Session,
  selectedOrganisationId?: string,
  requireExactSelection = false,
): Promise<ConsoleContext> {
  const person = await resolveSessionContext(session);
  const selected = selectedOrganisationId
    ? person.organisations.find(
        (organisation) =>
          organisation.organisationId === selectedOrganisationId,
      )
    : undefined;
  if (requireExactSelection && selectedOrganisationId && !selected) {
    throw new OrganisationAccessError(
      "Your account does not have access to that organisation.",
    );
  }
  return organisationContext(
    person,
    selected?.organisationId ?? person.organisations[0]!.organisationId,
  );
}

export async function requireOrganisationContext(
  organisationId: string,
): Promise<ConsoleContext> {
  if (!organisationId) {
    throw new OrganisationAccessError("Choose an organisation.");
  }
  return consoleContextFromSession(await requireSession(), organisationId, true);
}

export const requireConsoleContextForOrganisation =
  requireOrganisationContext;

export function activeOrganisationIdFromRequest(
  request: Request,
): string | undefined {
  const headerSelection = request.headers
    .get("x-blaktail-organisation")
    ?.trim();
  if (headerSelection) return headerSelection;

  for (const part of (request.headers.get("cookie") ?? "").split(";")) {
    const separator = part.indexOf("=");
    if (separator < 0) continue;
    if (part.slice(0, separator).trim() !== ACTIVE_ORGANISATION_COOKIE) continue;
    try {
      return decodeURIComponent(part.slice(separator + 1).trim()) || undefined;
    } catch {
      return undefined;
    }
  }
  return undefined;
}

/** Resolve the workspace cookie for organisation-scoped pages only. */
export async function requireConsoleContext(): Promise<ConsoleContext> {
  const session = await requireSession();
  const selectedOrganisationId = (await cookies()).get(
    ACTIVE_ORGANISATION_COOKIE,
  )?.value;
  return consoleContextFromSession(session, selectedOrganisationId);
}
