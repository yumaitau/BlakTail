// Pure coordinator path helpers. No I/O so bun tests can pin them.
import { UserFacingError } from "./errors";

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/**
 * A coordinator resource ID as one path segment. Coordinator IDs are UUIDs,
 * so anything else (form input such as `../acl` or `x?y`) is refused before
 * it can reach a different coordinator route; the value is encoded as well.
 */
export function idSegment(value: unknown): string {
  if (typeof value !== "string" || !UUID.test(value)) {
    throw new UserFacingError("That ID is not valid. Reload the page and try again.");
  }
  return encodeURIComponent(value);
}
