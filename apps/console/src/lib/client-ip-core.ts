// Pure client-address rules for rate limiting. No I/O so bun tests can pin them.

/**
 * Set by `src/proxy.ts` on every request (any client-sent value is dropped)
 * and read by Better Auth through `advanced.ipAddress.ipAddressHeaders`.
 */
export const CLIENT_IP_HEADER = "x-blaktail-client-ip";

/** Shared bucket for requests whose address cannot be trusted. */
export const UNTRUSTED_CLIENT_KEY = "untrusted-client";

const MAX_HOPS = 10;

/**
 * `BLAKTAIL_TRUSTED_PROXY_HOPS`: how many reverse proxies you run in front of
 * the console (1 behind a single AWS ALB). 0, unset or invalid means none, so
 * forwarding headers are ignored entirely.
 */
export function trustedProxyHops(value: string | undefined | null): number {
  const text = String(value ?? "").trim();
  if (!/^\d+$/.test(text)) return 0;
  const hops = Number(text);
  return hops <= MAX_HOPS ? hops : 0;
}

function plausibleAddress(value: string | undefined): string | null {
  const address = value?.trim();
  if (!address || address.length > 64) return null;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(address)) return address;
  if (address.includes(":") && /^[0-9a-fA-F:.]+$/.test(address)) {
    return address.toLowerCase();
  }
  return null;
}

type HeaderSource = { get(name: string): string | null };

/**
 * The client address as recorded by the outermost proxy you trust. Each
 * trusted proxy appends the address it received from, so the client is the
 * `hops`-th entry from the right of `X-Forwarded-For`; everything to its left
 * was supplied by the client and is ignored. `X-Real-IP` is used only when
 * proxies are trusted and the forwarded chain is absent. Returns `null` when
 * no trustworthy address exists.
 */
export function trustedClientAddress(headers: HeaderSource, hops: number): string | null {
  if (!Number.isInteger(hops) || hops <= 0) return null;
  const forwarded = headers.get("x-forwarded-for");
  if (forwarded !== null) {
    const chain = forwarded
      .split(",")
      .map((entry) => entry.trim())
      .filter(Boolean);
    if (chain.length < hops) return null;
    return plausibleAddress(chain[chain.length - hops]);
  }
  return plausibleAddress(headers.get("x-real-ip") ?? undefined);
}
