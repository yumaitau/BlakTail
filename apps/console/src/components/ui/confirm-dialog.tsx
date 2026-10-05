"use client";

import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Button } from "./button";

/**
 * Confirmation for destructive or consequential actions. Uses the native
 * modal `<dialog>`: focus is trapped, Escape cancels, the rest of the page is
 * inert, and focus returns to the opener on close. Cancel gets initial focus
 * so Enter never confirms by accident.
 *
 * `confirmText` adds type-to-confirm: the confirm button stays disabled until
 * the person types that exact text (use the device or resource name).
 */
export function ConfirmDialog({
  open,
  title,
  description,
  confirmLabel,
  cancelLabel = "Cancel",
  tone = "danger",
  confirmText,
  pending = false,
  onConfirm,
  onCancel,
  children,
}: {
  open: boolean;
  title: string;
  description?: ReactNode;
  confirmLabel: string;
  cancelLabel?: string;
  tone?: "danger" | "primary";
  confirmText?: string;
  pending?: boolean;
  onConfirm: () => void;
  onCancel: () => void;
  children?: ReactNode;
}) {
  const dialog = useRef<HTMLDialogElement>(null);
  const cancel = useRef<HTMLButtonElement>(null);
  const [typed, setTyped] = useState("");
  const titleId = useId();
  const descriptionId = useId();
  const inputId = useId();

  useEffect(() => {
    const element = dialog.current;
    if (!element) return;
    if (open && !element.open) {
      element.showModal();
      cancel.current?.focus();
    } else if (!open && element.open) {
      element.close();
    }
  }, [open]);

  useEffect(() => {
    // Reset the typed text each time the dialog closes.
    // eslint-disable-next-line react-hooks/set-state-in-effect
    if (!open) setTyped("");
  }, [open]);

  const matches = !confirmText || typed.trim() === confirmText;

  return (
    <dialog
      ref={dialog}
      className="ui-dialog"
      aria-labelledby={titleId}
      aria-describedby={description ? descriptionId : undefined}
      onCancel={(event) => {
        event.preventDefault();
        if (!pending) onCancel();
      }}
      onClick={(event) => {
        // A click on the backdrop (the dialog element itself) cancels.
        if (event.target === dialog.current && !pending) onCancel();
      }}
    >
      <form
        className="ui-dialog-body"
        method="dialog"
        onSubmit={(event) => {
          event.preventDefault();
          if (matches && !pending) onConfirm();
        }}
      >
        <h2 id={titleId}>{title}</h2>
        {description ? (
          <div id={descriptionId} className="ui-dialog-description">
            {description}
          </div>
        ) : null}
        {children}
        {confirmText ? (
          <div className="ui-field">
            <label htmlFor={inputId} className="ui-field-label">
              Type <strong className="mono">{confirmText}</strong> to confirm
            </label>
            <input
              id={inputId}
              value={typed}
              onChange={(event) => setTyped(event.target.value)}
              autoComplete="off"
              spellCheck={false}
            />
          </div>
        ) : null}
        <div className="ui-dialog-actions">
          <Button ref={cancel} variant="secondary" onClick={onCancel} disabled={pending}>
            {cancelLabel}
          </Button>
          <Button
            type="submit"
            variant={tone === "danger" ? "danger" : "primary"}
            loading={pending}
            disabled={!matches}
          >
            {confirmLabel}
          </Button>
        </div>
      </form>
    </dialog>
  );
}
