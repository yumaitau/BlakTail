"use client";

import {
  useCallback,
  useEffect,
  useRef,
  useSyncExternalStore,
} from "react";
import { AlertCircle, AlertTriangle, CheckCircle2, Info, X } from "lucide-react";

/*
 * Toasts report the outcome of something the person just did ("Device
 * renamed"). They are not for page-load errors (use <Alert>) or for field
 * errors (use <FormField error>).
 *
 *   toast.success("Device renamed");
 *   toast.error("Couldn't rename the device.", { reference: "7F3A9C21" });
 *   toastResult(result, { success: "Device renamed" });   // ActionResult
 *
 * Success and info dismiss themselves after 5 s (paused while hovered or
 * focused). Warnings stay 8 s. Errors stay until dismissed. At most three
 * show at once; the oldest goes first.
 */

export type ToastTone = "success" | "info" | "warning" | "error";

export type ToastOptions = {
  /** Second line of detail. */
  description?: string;
  /** Error reference for support, shown as "Reference 7F3A9C21". */
  reference?: string;
  /** Milliseconds; 0 keeps it until dismissed. */
  duration?: number;
};

type ToastItem = ToastOptions & {
  id: number;
  tone: ToastTone;
  message: string;
};

const MAX_TOASTS = 3;
const DEFAULT_DURATION: Record<ToastTone, number> = {
  success: 5000,
  info: 5000,
  warning: 8000,
  error: 0,
};

let items: ToastItem[] = [];
let nextId = 1;
const listeners = new Set<() => void>();

function emit() {
  for (const listener of listeners) listener();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => {
    listeners.delete(listener);
  };
}

function snapshot() {
  return items;
}

const EMPTY: ToastItem[] = [];
function serverSnapshot() {
  return EMPTY;
}

function show(tone: ToastTone, message: string, options: ToastOptions = {}): number {
  const id = nextId++;
  const item: ToastItem = {
    id,
    tone,
    message,
    ...options,
    duration: options.duration ?? DEFAULT_DURATION[tone],
  };
  // Replace an identical visible toast instead of stacking duplicates.
  const rest = items.filter(
    (existing) => !(existing.tone === tone && existing.message === message),
  );
  items = [...rest, item].slice(-MAX_TOASTS);
  emit();
  return id;
}

export function dismissToast(id: number) {
  items = items.filter((item) => item.id !== id);
  emit();
}

export const toast = {
  success: (message: string, options?: ToastOptions) => show("success", message, options),
  info: (message: string, options?: ToastOptions) => show("info", message, options),
  warning: (message: string, options?: ToastOptions) => show("warning", message, options),
  error: (message: string, options?: ToastOptions) => show("error", message, options),
  dismiss: dismissToast,
};

/** Same object as `toast`, for code that prefers hooks. */
export function useToast() {
  return toast;
}

type ResultLike =
  | { ok: true }
  | { ok: false; error: string; ref?: string; fieldErrors?: Record<string, string> };

/**
 * Show a server-action result as a toast. Returns field errors (or an empty
 * object) so a form can show them inline:
 *
 *   const result = await renameDeviceAction(formData);
 *   const fieldErrors = toastResult(result, { success: "Device renamed" });
 *
 * When the failure is only about fields, pass `{ errorToast: false }` and
 * render the field errors instead of a toast.
 */
export function toastResult(
  result: ResultLike,
  options: { success?: string; successDescription?: string; errorToast?: boolean } = {},
): Record<string, string> {
  if (result.ok) {
    if (options.success) toast.success(options.success, { description: options.successDescription });
    return {};
  }
  const fieldErrors = result.fieldErrors ?? {};
  if (options.errorToast !== false || Object.keys(fieldErrors).length === 0) {
    toast.error(result.error, { reference: result.ref });
  }
  return fieldErrors;
}

/**
 * For forms driven by `useActionState`: toasts each new result once.
 *
 *   const [state, formAction] = useActionState(saveAction, null);
 *   const fieldErrors = useActionToast(state, { success: "Policy published" });
 */
export function useActionToast(
  result: ResultLike | null | undefined,
  options: { success?: string; errorToast?: boolean } = {},
): Record<string, string> {
  const seen = useRef<ResultLike | null | undefined>(null);
  const { success, errorToast } = options;
  useEffect(() => {
    if (!result || seen.current === result) return;
    seen.current = result;
    toastResult(result, { success, errorToast });
  }, [result, success, errorToast]);
  return result && !result.ok ? (result.fieldErrors ?? {}) : {};
}

const ICONS = {
  success: CheckCircle2,
  info: Info,
  warning: AlertTriangle,
  error: AlertCircle,
} as const;

/** Mount once, in the root layout. */
export function Toaster() {
  const list = useSyncExternalStore(subscribe, snapshot, serverSnapshot);
  const polite = list.filter((item) => item.tone !== "error");
  const urgent = list.filter((item) => item.tone === "error");
  return (
    <div className="toaster">
      {/* Separate live regions so errors interrupt and successes don't. */}
      <div className="toast-region" role="region" aria-label="Notifications">
        <ol className="toast-list" aria-live="assertive" aria-relevant="additions">
          {urgent.map((item) => (
            <ToastCard key={item.id} item={item} />
          ))}
        </ol>
        <ol className="toast-list" aria-live="polite" aria-relevant="additions">
          {polite.map((item) => (
            <ToastCard key={item.id} item={item} />
          ))}
        </ol>
      </div>
    </div>
  );
}

function ToastCard({ item }: { item: ToastItem }) {
  const Icon = ICONS[item.tone];
  const remaining = useRef(item.duration ?? 0);
  const startedAt = useRef(0);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hovered = useRef(false);
  const focused = useRef(false);

  const stop = useCallback(() => {
    if (timer.current) {
      clearTimeout(timer.current);
      timer.current = null;
      remaining.current -= Date.now() - startedAt.current;
    }
  }, []);

  const start = useCallback(() => {
    if (!item.duration || timer.current || hovered.current || focused.current) return;
    startedAt.current = Date.now();
    timer.current = setTimeout(() => dismissToast(item.id), Math.max(remaining.current, 1000));
  }, [item.duration, item.id]);

  useEffect(() => {
    start();
    return () => {
      if (timer.current) clearTimeout(timer.current);
    };
  }, [start]);

  return (
    <li
      className={`toast toast-${item.tone}`}
      onMouseEnter={() => {
        hovered.current = true;
        stop();
      }}
      onMouseLeave={() => {
        hovered.current = false;
        start();
      }}
      onFocus={() => {
        focused.current = true;
        stop();
      }}
      onBlur={(event) => {
        if (event.currentTarget.contains(event.relatedTarget as Node | null)) return;
        focused.current = false;
        start();
      }}
    >
      <Icon className="toast-icon" aria-hidden="true" size={18} />
      <div className="toast-body">
        <p className="toast-message">
          <span className="visually-hidden">
            {item.tone === "error" ? "Error: " : item.tone === "warning" ? "Warning: " : ""}
          </span>
          {item.message}
        </p>
        {item.description ? <p className="toast-description">{item.description}</p> : null}
        {item.reference ? <p className="ui-ref">Reference {item.reference}</p> : null}
      </div>
      <button
        type="button"
        className="icon-button toast-close"
        aria-label="Dismiss notification"
        onClick={() => dismissToast(item.id)}
      >
        <X aria-hidden="true" size={16} />
      </button>
    </li>
  );
}
