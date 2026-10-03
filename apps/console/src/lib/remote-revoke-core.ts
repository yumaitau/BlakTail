import { createHmac, randomUUID } from "node:crypto";
import { can, type OrgRole } from "./roles";

/** Must match `REVOKE_USER_ACTION` in blaktail-coord/src/remote_access.rs. */
export const REVOKE_USER_ACTION = "remote_access.revoke_user";

/** Who removed the access when no person did: SCIM or directory sweeps. */
export type RevokeSource = "scim" | "directory";

/** A membership that is not active, or lacks the permission, keeps no sessions. */
export function needsRemoteRevoke(next: { role: string; status: string }): boolean {
  return !(next.status === "active" && can(next.role as OrgRole, "use_remote_sessions"));
}

/**
 * A service assertion the coordinator accepts only for revoking one
 * person's remote sessions, so SCIM deprovisioning (which has no console
 * session) can end them.
 */
export function signRevokeAssertion(input: {
  coordOrgId: string;
  source: RevokeSource;
  secret: string;
  now?: number;
  jti?: string;
}): string {
  if (Buffer.byteLength(input.secret) < 32) {
    throw new Error("BLAKTAIL_AUTH_HMAC_SECRET must be at least 32 bytes.");
  }
  const issuedAt = input.now ?? Math.floor(Date.now() / 1000);
  const payload = Buffer.from(
    JSON.stringify({
      sub: `system:${input.source}`,
      org_id: input.coordOrgId,
      role: "service",
      name: input.source === "scim" ? "SCIM provisioning" : "Directory sync",
      email: "",
      iss: "blaktail-console",
      aud: "blaktail-coord",
      iat: issuedAt,
      exp: issuedAt + 60,
      jti: input.jti ?? randomUUID(),
      action: REVOKE_USER_ACTION,
    }),
  ).toString("base64url");
  const signature = createHmac("sha256", input.secret).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

/** Asks the coordinator to revoke every open session and ticket for a person. */
export async function postUserRevoke(
  input: { coordOrgId: string; userId: string; source: RevokeSource },
  deps: { baseUrl: string; secret: string; fetch: typeof fetch },
): Promise<number> {
  const res = await deps.fetch(
    `${deps.baseUrl.replace(/\/$/, "")}/v1/orgs/${input.coordOrgId}/remote-access/users/${encodeURIComponent(input.userId)}/revoke`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${signRevokeAssertion({
          coordOrgId: input.coordOrgId,
          source: input.source,
          secret: deps.secret,
        })}`,
        "content-type": "application/json",
      },
      body: "{}",
      cache: "no-store",
    },
  );
  if (!res.ok) throw new Error(`Coordinator returned ${res.status}`);
  const body = (await res.json()) as { revoked?: number };
  return body.revoked ?? 0;
}
