import { eq } from "drizzle-orm";
import { db } from "./db/client";
import { identityProvider } from "./db/schema";
import { emailDomainAllowed } from "./oidc-jwt";

export async function discoverSso(
  email: string,
): Promise<{ organisationId: string } | null> {
  const domain = email.split("@")[1]?.trim().toLowerCase();
  if (!domain) return null;
  const providers = await db()
    .select({
      organisationId: identityProvider.organisationId,
      allowDomainsJson: identityProvider.allowDomainsJson,
      enabled: identityProvider.enabled,
    })
    .from(identityProvider)
    .where(eq(identityProvider.enabled, true));
  const matches = providers.filter(
    (provider) =>
      provider.allowDomainsJson.length > 0 &&
      emailDomainAllowed(email, provider.allowDomainsJson),
  );
  if (matches.length !== 1) return null;
  return { organisationId: matches[0]!.organisationId };
}
