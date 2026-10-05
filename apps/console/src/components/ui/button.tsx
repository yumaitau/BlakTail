import type { ButtonHTMLAttributes, ReactNode, Ref } from "react";

export type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "quiet-danger";

const VARIANT_CLASS: Record<ButtonVariant, string> = {
  primary: "",
  secondary: "secondary",
  ghost: "ghost",
  danger: "danger",
  "quiet-danger": "quiet-danger",
};

/**
 * Standard button. `loading` shows a spinner, keeps the width steady, sets
 * `aria-busy` and disables the button so it can't be pressed twice.
 */
export function Button({
  variant = "primary",
  size = "md",
  loading = false,
  loadingLabel,
  icon,
  className,
  disabled,
  children,
  type = "button",
  ref,
  ...rest
}: ButtonHTMLAttributes<HTMLButtonElement> & {
  ref?: Ref<HTMLButtonElement>;
  variant?: ButtonVariant;
  size?: "sm" | "md";
  loading?: boolean;
  /** Text while loading, e.g. "Saving…". Defaults to the normal label. */
  loadingLabel?: string;
  icon?: ReactNode;
}) {
  const classes = [
    "ui-button",
    VARIANT_CLASS[variant],
    size === "sm" ? "ui-button-sm" : "",
    className ?? "",
  ]
    .filter(Boolean)
    .join(" ");
  return (
    <button
      {...rest}
      ref={ref}
      type={type}
      className={classes}
      disabled={disabled || loading}
      aria-busy={loading || undefined}
    >
      {loading ? <Spinner /> : icon}
      <span>{loading && loadingLabel ? loadingLabel : children}</span>
    </button>
  );
}

export function Spinner({ label }: { label?: string }) {
  return (
    <span className="ui-spinner" role={label ? "status" : undefined} aria-hidden={label ? undefined : true}>
      {label ? <span className="visually-hidden">{label}</span> : null}
    </span>
  );
}
