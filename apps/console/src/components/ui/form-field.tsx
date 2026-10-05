"use client";

import {
  cloneElement,
  isValidElement,
  useId,
  type ReactElement,
  type ReactNode,
} from "react";
import { AlertCircle } from "lucide-react";

type ControlProps = {
  id?: string;
  required?: boolean;
  "aria-describedby"?: string;
  "aria-invalid"?: boolean;
};

/**
 * Label, optional hint, the control, and an error line. Wires `id`,
 * `aria-describedby`, `aria-invalid` and `required` onto the single child
 * control, so callers write plain `<input name="..." />`.
 */
export function FormField({
  label,
  hint,
  error,
  required = false,
  className,
  children,
}: {
  label: ReactNode;
  hint?: ReactNode;
  error?: string | null;
  required?: boolean;
  className?: string;
  children: ReactElement<ControlProps>;
}) {
  const autoId = useId();
  const controlId = (isValidElement(children) && children.props.id) || `field-${autoId}`;
  const hintId = hint ? `${controlId}-hint` : undefined;
  const errorId = error ? `${controlId}-error` : undefined;
  const describedBy =
    [children.props["aria-describedby"], hintId, errorId].filter(Boolean).join(" ") || undefined;

  return (
    <div className={["ui-field", error ? "has-error" : "", className].filter(Boolean).join(" ")}>
      <label htmlFor={controlId} className="ui-field-label">
        {label}
        {required ? (
          <>
            <span className="ui-required" aria-hidden="true">
              *
            </span>
            <span className="visually-hidden"> (required)</span>
          </>
        ) : null}
      </label>
      {hint ? (
        <p id={hintId} className="ui-field-hint">
          {hint}
        </p>
      ) : null}
      {cloneElement(children, {
        id: controlId,
        required: required || children.props.required,
        "aria-describedby": describedBy,
        "aria-invalid": error ? true : undefined,
      })}
      {error ? (
        <p id={errorId} className="ui-field-error">
          <AlertCircle aria-hidden="true" size={14} />
          {error}
        </p>
      ) : null}
    </div>
  );
}
