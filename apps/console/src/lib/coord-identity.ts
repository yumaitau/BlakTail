import "server-only";

import { coordFetch, coordError } from "./coord";
import { permissionReason } from "./roles";
import type { ConsoleContext } from "./session";

export type RotatedApiClient = {
  id: string;
  name: string;
  token: string;
  token_prefix: string;
  scopes: string[];
  expires_at: number | null;
};

function requireApiClientPermission(ctx: ConsoleContext) {
  const denied = permissionReason(ctx.role, "manage_api_clients");
  if (denied) throw new Error(denied);
}

/** New secret; the old secret and its OAuth access tokens stop at once. */
export async function rotateApiClient(
  ctx: ConsoleContext,
  clientId: string,
  expiresInSeconds?: number,
): Promise<RotatedApiClient> {
  requireApiClientPermission(ctx);
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/api-clients/${encodeURIComponent(clientId)}/rotate`,
    {
      method: "POST",
      ctx,
      body: JSON.stringify(
        expiresInSeconds ? { expires_in_seconds: expiresInSeconds } : {},
      ),
    },
  );
  if (!res.ok) throw await coordError(res);
  return res.json() as Promise<RotatedApiClient>;
}

export async function setApiClientSuspended(
  ctx: ConsoleContext,
  clientId: string,
  suspended: boolean,
): Promise<void> {
  requireApiClientPermission(ctx);
  const res = await coordFetch(
    `/v1/orgs/${ctx.coordOrgId}/api-clients/${encodeURIComponent(clientId)}/${
      suspended ? "suspend" : "resume"
    }`,
    { method: "POST", ctx },
  );
  if (!res.ok) throw await coordError(res);
}
