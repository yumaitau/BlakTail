import type { HTMLAttributes, ReactNode } from "react";

/** A plain surface. Don't nest cards inside cards. */
export function Card({
  className,
  children,
  ...rest
}: HTMLAttributes<HTMLDivElement>) {
  return (
    <div {...rest} className={["panel", className].filter(Boolean).join(" ")}>
      {children}
    </div>
  );
}

/**
 * A titled block of a page (a card with a header). `id` makes it linkable;
 * the heading labels the region for screen readers.
 */
export function Section({
  id,
  title,
  description,
  actions,
  children,
  className,
  headingLevel = 2,
}: {
  id?: string;
  title: string;
  description?: ReactNode;
  actions?: ReactNode;
  children?: ReactNode;
  className?: string;
  headingLevel?: 2 | 3;
}) {
  const headingId = id ? `${id}-title` : undefined;
  const Heading = headingLevel === 2 ? "h2" : "h3";
  return (
    <section
      id={id}
      aria-labelledby={headingId}
      className={["panel ui-section", className].filter(Boolean).join(" ")}
    >
      <div className="ui-section-header">
        <div className="ui-section-text">
          <Heading id={headingId}>{title}</Heading>
          {description ? <p className="muted">{description}</p> : null}
        </div>
        {actions ? <div className="ui-section-actions">{actions}</div> : null}
      </div>
      {children}
    </section>
  );
}
