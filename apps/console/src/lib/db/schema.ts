import { relations, sql } from "drizzle-orm";
import {
  bigint,
  boolean,
  check,
  index,
  integer,
  jsonb,
  pgTable,
  text,
  timestamp,
  uniqueIndex,
} from "drizzle-orm/pg-core";

export const user = pgTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: boolean("email_verified").notNull().default(false),
  image: text("image"),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
});

export const session = pgTable("session", {
  id: text("id").primaryKey(),
  expiresAt: timestamp("expires_at").notNull(),
  token: text("token").notNull().unique(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
  updatedAt: timestamp("updated_at").notNull().defaultNow(),
  ipAddress: text("ip_address"),
  userAgent: text("user_agent"),
  userId: text("user_id")
    .notNull()
    .references(() => user.id, { onDelete: "cascade" }),
});

export const account = pgTable(
  "account",
  {
    id: text("id").primaryKey(),
    issuer: text("issuer").notNull(),
    accountId: text("account_id").notNull(),
    providerId: text("provider_id").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    idToken: text("id_token"),
    accessTokenExpiresAt: timestamp("access_token_expires_at"),
    refreshTokenExpiresAt: timestamp("refresh_token_expires_at"),
    scope: text("scope"),
    password: text("password"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
    updatedAt: timestamp("updated_at").notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("account_issuer_account_id_unique").on(
      table.issuer,
      table.accountId,
    ),
  ],
);

export const verification = pgTable("verification", {
  id: text("id").primaryKey(),
  identifier: text("identifier").notNull(),
  value: text("value").notNull(),
  expiresAt: timestamp("expires_at").notNull(),
  createdAt: timestamp("created_at").defaultNow(),
  updatedAt: timestamp("updated_at").defaultNow(),
});

export const rateLimit = pgTable(
  "rate_limit",
  {
    id: text("id").primaryKey(),
    key: text("key").notNull(),
    count: integer("count").notNull(),
    lastRequest: bigint("last_request", { mode: "number" }).notNull(),
  },
  (table) => [uniqueIndex("rate_limit_key_unique").on(table.key)],
);

/** Organisation membership mirrored to the Rust coordinator. */
export const organisation = pgTable("organisation", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  /** Coordinator org UUID. Source of truth for tailnet authz lives on the coord. */
  coordOrgId: text("coord_org_id").notNull().unique(),
  createdAt: timestamp("created_at").notNull().defaultNow(),
});

/** A human principal. Better Auth users remain immutable login identities. */
export const person = pgTable("person", {
  id: text("id").primaryKey(),
  displayName: text("display_name").notNull(),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

/** The live link graph from a person to independently authenticated identities. */
export const personLoginIdentity = pgTable(
  "person_login_identity",
  {
    id: text("id").primaryKey(),
    personId: text("person_id")
      .notNull()
      .references(() => person.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    status: text("status")
      .notNull()
      .$type<"active" | "suspended">()
      .default("active"),
    linkedAt: timestamp("linked_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    suspendedAt: timestamp("suspended_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("person_login_identity_user_unique").on(table.userId),
    index("person_login_identity_person_status_idx").on(
      table.personId,
      table.status,
    ),
    check(
      "person_login_identity_status_check",
      sql.raw("\"status\" in ('active', 'suspended')"),
    ),
  ],
);

export const membership = pgTable(
  "membership",
  {
    id: text("id").primaryKey(),
    organisationId: text("organisation_id")
      .notNull()
      .references(() => organisation.id, { onDelete: "cascade" }),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    role: text("role").notNull().$type<"owner" | "admin" | "member">(),
    status: text("status")
      .notNull()
      .$type<"invited" | "active" | "suspended" | "removed">()
      .default("active"),
    createdAt: timestamp("created_at").notNull().defaultNow(),
  },
  (table) => [
    uniqueIndex("membership_org_user_unique").on(
      table.organisationId,
      table.userId,
    ),
    check(
      "membership_role_check",
      sql.raw("\"role\" in ('owner', 'admin', 'member')"),
    ),
    check(
      "membership_status_check",
      sql.raw("\"status\" in ('invited', 'active', 'suspended', 'removed')"),
    ),
  ],
);

export const identityProvider = pgTable(
  "identity_provider",
  {
    id: text("id").primaryKey(),
    organisationId: text("organisation_id")
      .notNull()
      .references(() => organisation.id, { onDelete: "cascade" }),
    issuer: text("issuer").notNull(),
    clientId: text("client_id").notNull(),
    clientSecret: text("client_secret").notNull(),
    enabled: boolean("enabled").notNull().default(false),
    allowDomainsJson: jsonb("allow_domains_json")
      .$type<string[]>()
      .notNull()
      .default([]),
    allowSubjectsJson: jsonb("allow_subjects_json")
      .$type<string[]>()
      .notNull()
      .default([]),
    allowGroupsJson: jsonb("allow_groups_json")
      .$type<string[]>()
      .notNull()
      .default([]),
    jitMembership: boolean("jit_membership").notNull().default(false),
    defaultRole: text("default_role")
      .notNull()
      .$type<"admin" | "member">()
      .default("member"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("identity_provider_org_issuer_unique").on(
      table.organisationId,
      table.issuer,
    ),
    check(
      "identity_provider_role_check",
      sql.raw("\"default_role\" in ('admin', 'member')"),
    ),
  ],
);

export const scimToken = pgTable(
  "scim_token",
  {
    id: text("id").primaryKey(),
    organisationId: text("organisation_id")
      .notNull()
      .references(() => organisation.id, { onDelete: "cascade" }),
    tokenHash: text("token_hash").notNull().unique(),
    label: text("label").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [index("scim_token_org_idx").on(table.organisationId)],
);

export const oidcLoginState = pgTable(
  "oidc_login_state",
  {
    id: text("id").primaryKey(),
    organisationId: text("organisation_id")
      .notNull()
      .references(() => organisation.id, { onDelete: "cascade" }),
    providerId: text("provider_id")
      .notNull()
      .references(() => identityProvider.id, { onDelete: "cascade" }),
    codeVerifier: text("code_verifier").notNull(),
    nonce: text("nonce").notNull(),
    redirectTo: text("redirect_to").notNull(),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [index("oidc_login_state_expiry_idx").on(table.expiresAt)],
);

/** Durable issuer+subject binding. Email is never the account key. */
export const externalIdentity = pgTable(
  "external_identity",
  {
    id: text("id").primaryKey(),
    organisationId: text("organisation_id")
      .notNull()
      .references(() => organisation.id, { onDelete: "cascade" }),
    providerId: text("provider_id")
      .notNull()
      .references(() => identityProvider.id, { onDelete: "cascade" }),
    issuer: text("issuer").notNull(),
    subject: text("subject").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    emailSnapshot: text("email_snapshot"),
    lastAuthenticatedAt: timestamp("last_authenticated_at", {
      withTimezone: true,
    }).notNull(),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("external_identity_issuer_subject_unique").on(
      table.issuer,
      table.subject,
    ),
    index("external_identity_user_idx").on(table.userId),
  ],
);

/** A named network account backed by one identity's organisation membership. */
export const networkAccount = pgTable(
  "network_account",
  {
    id: text("id").primaryKey(),
    membershipId: text("membership_id")
      .notNull()
      .references(() => membership.id, { onDelete: "cascade" }),
    loginIdentityUserId: text("login_identity_user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    organisationId: text("organisation_id")
      .notNull()
      .references(() => organisation.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    status: text("status")
      .notNull()
      .$type<"active" | "revoked">()
      .default("active"),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (table) => [
    uniqueIndex("network_account_membership_unique").on(table.membershipId),
    index("network_account_organisation_idx").on(table.organisationId),
    index("network_account_identity_active_idx").on(
      table.loginIdentityUserId,
      table.status,
    ),
    check(
      "network_account_status_check",
      sql.raw("\"status\" in ('active', 'revoked')"),
    ),
  ],
);

export const identityLinkChallenge = pgTable(
  "identity_link_challenge",
  {
    id: text("id").primaryKey(),
    tokenHash: text("token_hash").notNull().unique(),
    requesterPersonId: text("requester_person_id")
      .notNull()
      .references(() => person.id, { onDelete: "cascade" }),
    requesterUserId: text("requester_user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    requesterSessionId: text("requester_session_id")
      .notNull()
      .references(() => session.id, { onDelete: "cascade" }),
    targetUserId: text("target_user_id").references(() => user.id, {
      onDelete: "set null",
    }),
    status: text("status")
      .notNull()
      .$type<
        "pending" | "awaiting_owner" | "succeeded" | "rejected" | "expired"
      >()
      .default("pending"),
    failureCode: text("failure_code"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    authenticatedAt: timestamp("authenticated_at", { withTimezone: true }),
    completedAt: timestamp("completed_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("identity_link_challenge_open_person_unique")
      .on(table.requesterPersonId)
      .where(sql.raw("\"status\" in ('pending', 'awaiting_owner')")),
    check(
      "identity_link_challenge_status_check",
      sql.raw(
        "\"status\" in ('pending', 'awaiting_owner', 'succeeded', 'rejected', 'expired')",
      ),
    ),
  ],
);

export const identityLinkConflict = pgTable(
  "identity_link_conflict",
  {
    id: text("id").primaryKey(),
    challengeId: text("challenge_id")
      .notNull()
      .references(() => identityLinkChallenge.id, { onDelete: "cascade" }),
    organisationId: text("organisation_id")
      .notNull()
      .references(() => organisation.id, { onDelete: "cascade" }),
    requesterRole: text("requester_role")
      .notNull()
      .$type<"owner" | "admin" | "member">(),
    targetRole: text("target_role")
      .notNull()
      .$type<"owner" | "admin" | "member">(),
    resolvedRole: text("resolved_role").$type<"owner" | "admin" | "member">(),
    resolvedByUserId: text("resolved_by_user_id").references(() => user.id, {
      onDelete: "set null",
    }),
    resolvedAt: timestamp("resolved_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("identity_link_conflict_challenge_org_unique").on(
      table.challengeId,
      table.organisationId,
    ),
    check(
      "identity_link_conflict_roles_check",
      sql.raw(
        "\"requester_role\" in ('owner', 'admin', 'member') AND \"target_role\" in ('owner', 'admin', 'member') AND (\"resolved_role\" IS NULL OR \"resolved_role\" in ('owner', 'admin', 'member'))",
      ),
    ),
  ],
);

/** Owner-approved effective role while the underlying memberships stay intact. */
export const membershipRoleResolution = pgTable(
  "membership_role_resolution",
  {
    id: text("id").primaryKey(),
    personId: text("person_id")
      .notNull()
      .references(() => person.id, { onDelete: "cascade" }),
    organisationId: text("organisation_id")
      .notNull()
      .references(() => organisation.id, { onDelete: "cascade" }),
    effectiveRole: text("effective_role")
      .notNull()
      .$type<"owner" | "admin" | "member">(),
    membershipSignature: text("membership_signature").notNull(),
    resolvedByUserId: text("resolved_by_user_id").references(() => user.id, {
      onDelete: "set null",
    }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("membership_role_resolution_person_org_unique").on(
      table.personId,
      table.organisationId,
    ),
    check(
      "membership_role_resolution_role_check",
      sql.raw("\"effective_role\" in ('owner', 'admin', 'member')"),
    ),
  ],
);

export const bootstrapState = pgTable(
  "bootstrap_state",
  {
    id: text("id").primaryKey(),
    status: text("status")
      .notNull()
      .$type<"uninitialised" | "claimable" | "provisioning" | "locked">(),
    tokenHash: text("token_hash"),
    tokenExpiresAt: timestamp("token_expires_at", { withTimezone: true }),
    provisioningUserId: text("provisioning_user_id"),
    provisioningOrganisationId: text("provisioning_organisation_id"),
    provisioningCoordOrgId: text("provisioning_coord_org_id"),
    provisioningEmail: text("provisioning_email"),
    provisioningOwnerName: text("provisioning_owner_name"),
    provisioningOrganisationName: text("provisioning_organisation_name"),
    lockedAt: timestamp("locked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  () => [
    check("bootstrap_state_singleton_check", sql.raw("\"id\" = 'primary'")),
    check(
      "bootstrap_state_status_check",
      sql.raw(
        "\"status\" in ('uninitialised', 'claimable', 'provisioning', 'locked')",
      ),
    ),
  ],
);

export const invitation = pgTable(
  "invitation",
  {
    id: text("id").primaryKey(),
    organisationId: text("organisation_id")
      .notNull()
      .references(() => organisation.id, { onDelete: "cascade" }),
    email: text("email").notNull(),
    role: text("role").notNull().$type<"admin" | "member">(),
    tokenHash: text("token_hash").notNull().unique(),
    inviterUserId: text("inviter_user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    status: text("status")
      .notNull()
      .$type<"pending" | "accepted" | "revoked">()
      .default("pending"),
    expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
    acceptedAt: timestamp("accepted_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
    createdAt: timestamp("created_at", { withTimezone: true })
      .notNull()
      .defaultNow(),
  },
  (table) => [
    uniqueIndex("invitation_pending_org_email_unique")
      .on(table.organisationId, table.email)
      .where(sql.raw("\"status\" = 'pending'")),
    check("invitation_role_check", sql.raw("\"role\" in ('admin', 'member')")),
    check(
      "invitation_status_check",
      sql.raw("\"status\" in ('pending', 'accepted', 'revoked')"),
    ),
  ],
);

export const consoleAuditEvent = pgTable("console_audit_event", {
  id: text("id").primaryKey(),
  organisationId: text("organisation_id").references(() => organisation.id, {
    onDelete: "cascade",
  }),
  actorUserId: text("actor_user_id"),
  actorEmail: text("actor_email").notNull().default(""),
  actorRole: text("actor_role").notNull(),
  source: text("source").notNull(),
  action: text("action").notNull(),
  result: text("result").notNull(),
  targetType: text("target_type").notNull(),
  targetId: text("target_id"),
  details: jsonb("details").notNull().default({}),
  createdAt: timestamp("created_at", { withTimezone: true })
    .notNull()
    .defaultNow(),
});

export const userRelations = relations(user, ({ many }) => ({
  sessions: many(session),
  accounts: many(account),
  memberships: many(membership),
}));

export const organisationRelations = relations(organisation, ({ many }) => ({
  memberships: many(membership),
}));

export const membershipRelations = relations(membership, ({ one }) => ({
  organisation: one(organisation, {
    fields: [membership.organisationId],
    references: [organisation.id],
  }),
  user: one(user, {
    fields: [membership.userId],
    references: [user.id],
  }),
}));
