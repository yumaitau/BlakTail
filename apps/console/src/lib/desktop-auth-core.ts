/**
 * Pure helpers for the desktop and mobile app sign-in bridge. No database or
 * Next.js imports so the logic can be tested with `bun test`.
 */

/** The only callback the console hands codes to. */
export const DESKTOP_REDIRECT_URI = "blaktail://auth/callback";

/**
 * Accepts exactly `blaktail://auth/callback` (no query, fragment, userinfo,
 * port or extra path). Anything else is refused rather than normalised.
 */
export function validDesktopRedirectUri(value: string | null | undefined): string | null {
  if (typeof value !== "string" || value !== DESKTOP_REDIRECT_URI) return null;
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    return null;
  }
  if (
    parsed.protocol !== "blaktail:" ||
    parsed.host !== "auth" ||
    parsed.pathname !== "/callback" ||
    parsed.search ||
    parsed.hash ||
    parsed.username ||
    parsed.password
  ) {
    return null;
  }
  return DESKTOP_REDIRECT_URI;
}

/** Escapes text for an HTML attribute or text node. */
export function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
