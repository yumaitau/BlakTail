import "server-only";

import {
  CoordError,
  fieldErrorsFor,
  parseCoordEnvelope,
  toUserError,
  userErrorText,
  type DescribeOptions,
  type UserError,
} from "./errors";

export { CoordError, UserFacingError } from "./errors";

/** Failed server-action result. `error` is safe to show; `ref` finds the log line. */
export type ActionFailure = {
  ok: false;
  error: string;
  ref?: string;
  fieldErrors?: Record<string, string>;
};

/** The coordinator role attached to each response by `coordFetch`, for 403 wording. */
const responseRoles = new WeakMap<Response, string>();

export function rememberResponseRole(res: Response, role: string): void {
  responseRoles.set(res, role);
}

/** One JSON log line per failure: the full detail stays server-side. */
export function logServerError(scope: string, error: unknown, user?: UserError): void {
  if (error instanceof CoordError) {
    if (error.logged) return;
    error.logged = true;
  }
  const entry: Record<string, unknown> = {
    level: "error",
    scope,
    ref: user?.ref ?? (error instanceof CoordError ? error.ref : undefined),
    kind: user?.kind,
  };
  if (error instanceof CoordError) {
    entry.status = error.status;
    entry.code = error.code;
    entry.coordinator_request_id = error.requestId;
    entry.detail = error.detail;
  } else if (error instanceof Error) {
    entry.name = error.name;
    entry.message = error.message;
    entry.stack = error.stack;
  } else {
    entry.value = String(error);
  }
  console.error(JSON.stringify(entry));
}

/**
 * Turn a failed coordinator response into a `CoordError` (user-safe message,
 * short reference) and log the raw envelope. Use as `throw await coordError(res)`.
 */
export async function coordError(
  res: Response,
  options: DescribeOptions = {},
): Promise<CoordError> {
  let text = "";
  try {
    text = await res.text();
  } catch {
    /* body unreadable: status is enough */
  }
  const descriptor = parseCoordEnvelope(res.status, text, res.headers.get("retry-after"));
  const role = options.role ?? responseRoles.get(res);
  const error = new CoordError(descriptor, { ...options, role });
  logServerError(`coordinator ${res.status} ${new URL(res.url || "http://x/").pathname}`, error);
  return error;
}

/** Map anything caught in a server action to the standard failure shape. */
export function actionFailure(
  error: unknown,
  fallback: string,
  scope = "action",
  options: { fields?: DescribeOptions["fields"] } = {},
): ActionFailure {
  const user = { ...toUserError(error, fallback) };
  if (
    options.fields &&
    !user.fieldErrors &&
    user.kind === "validation" &&
    error instanceof CoordError
  ) {
    user.fieldErrors = fieldErrorsFor(user.message, error.detail, options.fields);
  }
  if (user.ref || error instanceof CoordError) logServerError(scope, error, user);
  return {
    ok: false,
    error: user.message,
    ...(user.ref ? { ref: user.ref } : {}),
    ...(user.fieldErrors ? { fieldErrors: user.fieldErrors } : {}),
  };
}

/** One string (message plus reference) for server-rendered load errors. */
export function errorText(error: unknown, fallback: string, scope = "page"): string {
  const user = toUserError(error, fallback);
  if (user.ref || error instanceof CoordError) logServerError(scope, error, user);
  return userErrorText(user);
}

const STATUS_FOR_KIND: Record<UserError["kind"], number> = {
  validation: 400,
  sign_in: 401,
  permission: 403,
  suspended: 403,
  not_found: 404,
  gone: 410,
  conflict: 409,
  stale: 412,
  too_large: 413,
  rate_limited: 429,
  unavailable: 503,
  network: 502,
  timeout: 504,
  server: 500,
  unknown: 500,
};

/** JSON error response for route handlers: `{ error, ref? }` with a fitting status. */
export function jsonError(
  error: unknown,
  fallback: string,
  scope = "route",
  status?: number,
): Response {
  const user = toUserError(error, fallback);
  if (user.ref || error instanceof CoordError) logServerError(scope, error, user);
  const knownStatus = (error as { status?: unknown } | null)?.status;
  const code =
    status ??
    (error instanceof CoordError
      ? STATUS_FOR_KIND[user.kind]
      : typeof knownStatus === "number" && knownStatus >= 400 && knownStatus < 600
        ? knownStatus
        : STATUS_FOR_KIND[user.kind]);
  const headers: Record<string, string> = { "cache-control": "no-store" };
  if (user.retryAfter) headers["retry-after"] = String(user.retryAfter);
  return Response.json(
    { error: user.message, ...(user.ref ? { ref: user.ref } : {}) },
    { status: code, headers },
  );
}

export class BodyTooLargeError extends Error {
  readonly status = 413;
  constructor(limit: number) {
    super(`That request is too large. Keep it under ${Math.round(limit / 1024)} KB.`);
    this.name = "BodyTooLargeError";
  }
}

export class InvalidJsonError extends Error {
  readonly status = 400;
  constructor() {
    super("That request couldn't be read. Reload the page and try again.");
    this.name = "InvalidJsonError";
  }
}

/** Default JSON body cap for console route handlers. */
export const JSON_BODY_LIMIT = 64 * 1024;
/** SCIM group pushes can carry large member lists. */
export const SCIM_BODY_LIMIT = 1024 * 1024;

/**
 * Like `readJsonBody`, but returns `fallback` for unreadable JSON. An
 * oversized body still throws `BodyTooLargeError` (status 413).
 */
export async function readJsonBodyOr<T>(
  request: Request,
  fallback: T,
  limit = JSON_BODY_LIMIT,
): Promise<T> {
  try {
    return await readJsonBody<T>(request, limit);
  } catch (error) {
    if (error instanceof BodyTooLargeError) throw error;
    return fallback;
  }
}

/**
 * Read a JSON request body with a size cap. Checks Content-Length first, then
 * counts bytes while streaming so a missing or false header can't bypass it.
 */
export async function readJsonBody<T = unknown>(
  request: Request,
  limit = JSON_BODY_LIMIT,
): Promise<T> {
  const declared = Number(request.headers.get("content-length") ?? "");
  if (Number.isFinite(declared) && declared > limit) throw new BodyTooLargeError(limit);
  const reader = request.body?.getReader();
  if (!reader) throw new InvalidJsonError();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > limit) {
      await reader.cancel().catch(() => undefined);
      throw new BodyTooLargeError(limit);
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  try {
    return JSON.parse(new TextDecoder().decode(bytes)) as T;
  } catch {
    throw new InvalidJsonError();
  }
}
