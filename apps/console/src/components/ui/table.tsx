import type { ReactNode, TableHTMLAttributes, TdHTMLAttributes } from "react";

/**
 * Responsive table. On mobile (<= 800px):
 * - `mobile="scroll"` (default) keeps columns and scrolls sideways inside a
 *   focusable, labelled region (keyboard users can scroll it).
 * - `mobile="stack"` turns each row into a card; give every `<Td label="...">`
 *   so the column name shows beside the value.
 */
export function Table({
  label,
  mobile = "scroll",
  className,
  children,
  ...rest
}: TableHTMLAttributes<HTMLTableElement> & {
  /** Accessible name for the table and its scroll region. */
  label: string;
  mobile?: "scroll" | "stack";
}) {
  const classes = ["table", mobile === "stack" ? "table-stack" : "", className]
    .filter(Boolean)
    .join(" ");
  return (
    <div
      className="table-wrap ui-table-wrap"
      role={mobile === "scroll" ? "region" : undefined}
      aria-label={mobile === "scroll" ? label : undefined}
      tabIndex={mobile === "scroll" ? 0 : undefined}
    >
      <table {...rest} className={classes} aria-label={label}>
        {children}
      </table>
    </div>
  );
}

/** A cell that labels itself when the table stacks on mobile. */
export function Td({
  label,
  children,
  ...rest
}: TdHTMLAttributes<HTMLTableCellElement> & { label?: string }) {
  return (
    <td {...rest} data-label={label}>
      {children}
    </td>
  );
}

/** Full-width row for "nothing matches" inside a table body. */
export function EmptyRow({
  colSpan,
  children,
}: {
  colSpan: number;
  children: ReactNode;
}) {
  return (
    <tr className="ui-empty-row">
      <td colSpan={colSpan}>{children}</td>
    </tr>
  );
}
