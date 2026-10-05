// One place that turns coordinator and console failures into short,
// plain-English messages. Pure and isomorphic: safe in server code, client
// components and bun tests. Server logging lives in `server-errors.ts`.
//
// Rule: users see `message` (and `ref` when it helps support find the log
// line). They never see coordinator `error` text, codes, JSON, SQL or stacks,
// except a validation `detail` that passes `safeDetail`.

export type UserErrorKind =
  | "validation"
  | "sign_in"
  | "permission"
  | "suspended"
  | "not_found"
  | "gone"
  | "conflict"
  | "stale"
  | "too_large"
  | "rate_limited"
  | "unavailable"
  | "network"
  | "timeout"
  | "server"
  | "unknown";

export type UserError = {
  kind: UserErrorKind;
  /** Short, actionable, plain-English sentence(s). Safe to show. */
  message: string;
  /** Short reference for support, e.g. "7F3A9C21". Present for failures worth reporting. */
  ref?: string;
  /** Per-field messages for forms, keyed by form field name. */
  fieldErrors?: Record<string, string>;
  /** Trying again later may work (network, 5xx, 429, timeouts). */
  retryable: boolean;
  /** Seconds to wait before retrying (429 Retry-After). */
  retryAfter?: number;
};

export type ErrorDescriptor = {
  /** HTTP status from the coordinator or a console route, if any. */
  status?: number;
  /** Coordinator envelope `code` (bad_request, forbidden, conflict, ...). */
  code?: string;
  /** Coordinator envelope `error`/`message` text. Logged; shown only if safe. */
  detail?: string;
  /** Coordinator envelope `request_id`. */
  requestId?: string;
  retryAfter?: number;
  /** Transport failure rather than an HTTP response. */
  transport?: "network" | "timeout";
};

export type DescribeOptions = {
  /** Signed-in role label ("member", "Network admin") for permission messages. */
  role?: string;
  /** Map validation detail onto form fields: field name -> words that identify it. */
  fields?: Record<string, string[]>;
  /** Overrides by status (e.g. a page-specific 412 message). */
  messages?: Partial<Record<number, string>>;
};

const COORDINATOR_DOWN =
  "BlakTail couldn't reach the coordinator. Check your connection and try again in a moment.";

/** 8 upper-case hex characters from a request id, or a fresh random one. */
export function shortRef(requestId?: string | null): string {
  const hex = (requestId ?? "").replace(/[^0-9a-f]/giu, "");
  if (hex.length >= 8) return hex.slice(0, 8).toUpperCase();
  const bytes = new Uint8Array(4);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

const INTERNAL_PATTERNS: RegExp[] = [
  /[{}[\]<>`]/u, // JSON, markup, code
  /\bat\s+\S+\s+\(/u, // stack frame
  /\n/u,
  /\b(select|insert|update|delete)\b.+\b(from|into|set|where)\b/iu, // SQL
  /\b(sqlx?|postgres|sqlite|drizzle|database|constraint|violates|panic|unwrap|thread|stack|errno|econn\w*|enotfound|etimedout)\b/iu,
  /\b[A-Z][A-Z0-9]*_[A-Z0-9_]{2,}\b/u, // ENV_VAR or ERROR_CODE names
  /\bhttps?:\/\//iu,
  /\b(bearer|token|secret|password|hmac)\b\s*[:=]/iu,
  /\bfailed query\b/iu,
  /\b(undefined|null|NaN|is not a function|coordinator returned)\b/iu,
  /[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/iu, // raw ids
];

/**
 * A coordinator validation message is shown only when it is short, one line
 * and looks like a sentence, not internals. Returns it as a sentence or null.
 */
export function safeDetail(
  detail: string | undefined | null,
  maxLength = 160,
): string | null {
  if (!detail) return null;
  const text = detail.trim().replace(/^(conflict|invalid request|bad request):\s*/iu, "");
  if (!text || text.length > maxLength) return null;
  if (INTERNAL_PATTERNS.some((pattern) => pattern.test(text))) return null;
  const sentence = text.charAt(0).toUpperCase() + text.slice(1);
  return /[.!?]$/u.test(sentence) ? sentence : `${sentence}.`;
}

/** Coordinator envelope codes and the status each one is sent with. */
export const COORD_ERROR_CODES = {
  bad_request: 400,
  unauthorized: 401,
  forbidden: 403,
  suspended: 403,
  not_found: 404,
  gone: 410,
  precondition_failed: 412,
  rate_limited: 429,
  unavailable: 503,
  conflict: 409,
  internal_error: 500,
} as const;

function kindFor(descriptor: ErrorDescriptor): UserErrorKind {
  if (descriptor.transport) return descriptor.transport;
  switch (descriptor.code) {
    case "bad_request":
      return "validation";
    case "unauthorized":
      return "sign_in";
    case "forbidden":
      return "permission";
    case "suspended":
      return "suspended";
    case "not_found":
      return "not_found";
    case "gone":
      return "gone";
    case "precondition_failed":
      return "stale";
    case "rate_limited":
      return "rate_limited";
    case "unavailable":
      return "unavailable";
    case "conflict":
      return "conflict";
    case "internal_error":
      return "server";
  }
  const status = descriptor.status ?? 0;
  if (status === 400 || status === 422) return "validation";
  if (status === 401) return "sign_in";
  if (status === 403) return "permission";
  if (status === 404) return "not_found";
  if (status === 408 || status === 504) return "timeout";
  if (status === 409) return "conflict";
  if (status === 410) return "gone";
  if (status === 412 || status === 428) return "stale";
  if (status === 413) return "too_large";
  if (status === 429) return "rate_limited";
  if (status === 502 || status === 503) return "unavailable";
  if (status >= 500) return "server";
  return "unknown";
}

function waitPhrase(seconds: number | undefined): string {
  if (!seconds || seconds <= 0) return "Wait a moment, then try again.";
  if (seconds < 90) return `Try again in ${Math.ceil(seconds)} seconds.`;
  return `Try again in about ${Math.ceil(seconds / 60)} minutes.`;
}

export function fieldErrorsFor(
  message: string,
  detail: string | undefined,
  fields: DescribeOptions["fields"],
): Record<string, string> | undefined {
  if (!fields || !detail) return undefined;
  const haystack = detail.toLowerCase();
  const matched: Record<string, string> = {};
  for (const [field, words] of Object.entries(fields)) {
    if (words.some((word) => haystack.includes(word.toLowerCase()))) {
      matched[field] = message;
    }
  }
  return Object.keys(matched).length > 0 ? matched : undefined;
}

/** Map a coordinator/HTTP/transport failure to a user message. */
export function describeError(
  descriptor: ErrorDescriptor,
  options: DescribeOptions = {},
): UserError {
  const kind = kindFor(descriptor);
  const override = descriptor.status ? options.messages?.[descriptor.status] : undefined;
  const ref = shortRef(descriptor.requestId);
  const safe = safeDetail(descriptor.detail);
  const roleText = options.role ? `Your ${options.role.toLowerCase()} role` : "Your role";

  const base = (message: string, extra: Partial<UserError> = {}): UserError => ({
    kind,
    message: override ?? message,
    retryable: false,
    ...extra,
  });

  switch (kind) {
    case "validation": {
      const message = safe ?? "Some details weren't accepted. Check the form and try again.";
      return base(message, {
        fieldErrors: fieldErrorsFor(override ?? message, descriptor.detail, options.fields),
      });
    }
    case "sign_in":
      return base("Your session has ended. Sign in again to continue.");
    case "permission":
      return base(
        `${roleText} doesn't allow this. Ask an owner or admin of this organisation if you need it.`,
      );
    case "suspended":
      return base("This device is suspended by an administrator, so it can't be changed until it's resumed.");
    case "not_found":
      return base("We couldn't find that. It may have been removed. Reload the page to see the current list.");
    case "gone":
      return base("This request has expired. Start again to get a fresh one.");
    case "conflict":
      return base(
        safe
          ? `${safe} Reload to see the latest version.`
          : "Someone else changed this while you were editing. Reload to see the latest version, then try again.",
        { ref },
      );
    case "stale":
      return base(
        "This changed since the page loaded. Reload to see the latest version, then make your change again.",
      );
    case "too_large":
      return base("That's too large to send. Make it smaller and try again.");
    case "rate_limited":
      return base(`Too many requests in a short time. ${waitPhrase(descriptor.retryAfter)}`, {
        retryable: true,
        retryAfter: descriptor.retryAfter,
      });
    case "timeout":
      return base("The coordinator took too long to answer. Try again in a moment.", {
        ref,
        retryable: true,
      });
    case "network":
    case "unavailable":
      return base(COORDINATOR_DOWN, { ref, retryable: true });
    case "server":
      return base("Something went wrong on our side. Try again, and if it keeps happening, contact support with the reference.", {
        ref,
        retryable: true,
      });
    default:
      return base("Something went wrong. Try again, and if it keeps happening, contact support with the reference.", {
        ref,
        retryable: true,
      });
  }
}

/** Parse a coordinator response body (already read as text) into a descriptor. */
export function parseCoordEnvelope(
  status: number,
  bodyText: string,
  retryAfterHeader?: string | null,
): ErrorDescriptor {
  const descriptor: ErrorDescriptor = { status };
  const retryAfter = retryAfterHeader ? Number.parseInt(retryAfterHeader, 10) : NaN;
  if (Number.isFinite(retryAfter) && retryAfter >= 0) descriptor.retryAfter = retryAfter;
  try {
    const body = JSON.parse(bodyText) as {
      error?: unknown;
      message?: unknown;
      code?: unknown;
      request_id?: unknown;
    };
    if (typeof body.code === "string") descriptor.code = body.code;
    if (typeof body.request_id === "string") descriptor.requestId = body.request_id;
    const text = typeof body.message === "string" ? body.message : body.error;
    if (typeof text === "string") descriptor.detail = text;
  } catch {
    /* not JSON: keep status only */
  }
  return descriptor;
}

/**
 * A coordinator failure. `message` is already the user-safe text, so older
 * `error instanceof Error ? error.message : ...` call sites stay safe. Raw
 * coordinator text is kept on `detail` for server logs only.
 */
export class CoordError extends Error {
  readonly status: number;
  readonly code?: string;
  readonly ref?: string;
  readonly requestId?: string;
  readonly detail?: string;
  readonly user: UserError;
  /** Set once the server has logged this error, so it is logged only once. */
  logged = false;

  constructor(descriptor: ErrorDescriptor, options: DescribeOptions = {}) {
    const user = describeError(descriptor, options);
    super(user.message);
    this.name = "CoordError";
    this.status = descriptor.status ?? 0;
    this.code = descriptor.code;
    this.requestId = descriptor.requestId;
    this.detail = descriptor.detail;
    this.ref = user.ref;
    this.user = user;
  }
}

/** Throw this for a message written for people (validation, permission). */
export class UserFacingError extends Error {
  constructor(
    message: string,
    readonly fieldErrors?: Record<string, string>,
  ) {
    super(message);
    this.name = "UserFacingError";
  }
}

function isTimeout(error: Error): boolean {
  return error.name === "TimeoutError" || error.name === "AbortError";
}

function isNetwork(error: Error): boolean {
  const cause = (error as { cause?: { code?: unknown } }).cause;
  return (
    (error.name === "TypeError" && /fetch|network|load failed/iu.test(error.message)) ||
    (typeof cause?.code === "string" && /^(ECONN|ENOTFOUND|EAI_|EHOST|ENETUNREACH|UND_ERR)/u.test(cause.code))
  );
}

/**
 * Classify anything caught in a server action, route handler, page or client
 * component. Known console errors keep their message; anything else becomes a
 * generic message with a reference.
 */
export function toUserError(error: unknown, fallback: string): UserError {
  if (error instanceof CoordError) return error.user;
  if (error instanceof Error) {
    if (isTimeout(error)) return describeError({ transport: "timeout" });
    if (isNetwork(error)) return describeError({ transport: "network" });
    // Console code throws sentences written for people (validation,
    // permission). Keep one only if it reads like that; driver, library and
    // coordinator internals never pass `safeDetail`. Checked by content, not
    // class name, because production builds minify class names.
    const programmingError =
      error instanceof TypeError ||
      error instanceof ReferenceError ||
      error instanceof SyntaxError ||
      error instanceof RangeError;
    const safe = programmingError ? null : safeDetail(error.message, 240);
    if (safe) {
      const status = (error as { status?: unknown }).status;
      const fieldErrors = (error as { fieldErrors?: Record<string, string> }).fieldErrors;
      return {
        kind: status === 401 ? "sign_in" : status === 403 ? "permission" : "validation",
        message: safe,
        retryable: false,
        fieldErrors,
      };
    }
  }
  return {
    kind: "unknown",
    message: `${fallback.replace(/\.?$/u, ".")} Try again, and if it keeps happening, contact support with the reference.`,
    ref: shortRef(),
    retryable: true,
  };
}

/** "Message (Reference 7F3A9C21)" for places that only render one string. */
export function userErrorText(user: UserError): string {
  return user.ref ? `${user.message} Reference ${user.ref}.` : user.message;
}

/**
 * Better Auth client errors (`{ status, code, message }`) as user messages.
 * Codes come from better-auth's BASE_ERROR_CODES and the two-factor plugin.
 */
export function authErrorMessage(
  error: { status?: number; code?: string; message?: string } | null | undefined,
  fallback: string,
): UserError {
  const code = (error?.code ?? "").toUpperCase();
  const known: Record<string, string> = {
    INVALID_PASSWORD: "Your current password isn't right. Check it and try again.",
    INVALID_EMAIL_OR_PASSWORD: "That email and password don't match. Check them and try again.",
    PASSWORD_TOO_SHORT: "That password is too short. Use at least 10 characters.",
    PASSWORD_TOO_LONG: "That password is too long. Use 128 characters or fewer.",
    INVALID_CODE: "That code isn't right. Check your authenticator app and try again.",
    INVALID_TWO_FACTOR_COOKIE: "Your sign-in step expired. Sign in again.",
    TOO_MANY_ATTEMPTS: "Too many attempts. Wait a few minutes, then try again.",
    SESSION_EXPIRED: "Your session has ended. Sign in again to continue.",
    CREDENTIAL_ACCOUNT_NOT_FOUND: "This account signs in with single sign-on, so it has no password to change.",
  };
  if (code && known[code]) {
    return { kind: "validation", message: known[code], retryable: false };
  }
  if (!error) return toUserError(new Error(), fallback);
  if (error.status === 429) return describeError({ status: 429 });
  if (error.status && error.status >= 500) return describeError({ status: error.status });
  if (error.status === 401) return describeError({ status: 401 });
  return { kind: "validation", message: fallback, retryable: false };
}
