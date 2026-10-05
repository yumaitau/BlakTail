"use client";

import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import { Copy, KeyRound } from "lucide-react";
import { Button } from "./button";
import { toast } from "./toast";

/**
 * A secret shown exactly once (API token, SCIM token, recovery codes, agent
 * key, signing secret). Says so plainly, offers a copy button, and keeps the
 * secret on screen until the person confirms they've stored it. Focus moves
 * to the heading when it appears so screen readers announce it.
 */
export function SecretPanel({
  title,
  label,
  secret,
  description,
  onDone,
  doneLabel = "Done",
}: {
  /** e.g. "Copy the API token now". */
  title: string;
  /** What the secret is, for the copy toast and screen readers: "API token". */
  label: string;
  /** One string, or a list (recovery codes), shown one per line. */
  secret: string | string[];
  description?: ReactNode;
  onDone: () => void;
  doneLabel?: string;
}) {
  const headingRef = useRef<HTMLHeadingElement>(null);
  const [saved, setSaved] = useState(false);
  const headingId = useId();
  const checkId = useId();
  const text = Array.isArray(secret) ? secret.join("\n") : secret;

  useEffect(() => {
    headingRef.current?.focus();
  }, []);

  return (
    <section className="secret-panel" aria-labelledby={headingId}>
      <div className="secret-panel-head">
        <KeyRound aria-hidden="true" size={18} className="secret-panel-icon" />
        <h3 id={headingId} ref={headingRef} tabIndex={-1}>
          {title}
        </h3>
        <span className="badge pending no-dot">Shown once</span>
      </div>
      <p className="secret-panel-text">
        {description ??
          "This is the only time it is shown. Store it in your password manager or secrets vault. Don't paste it into chat, tickets or email."}
      </p>
      {Array.isArray(secret) ? (
        <ol className="secret-panel-value secret-panel-list mono" aria-label={label}>
          {secret.map((line) => (
            <li key={line}>{line}</li>
          ))}
        </ol>
      ) : (
        <p className="secret-panel-value mono" aria-label={label}>
          {secret}
        </p>
      )}
      <div className="secret-panel-actions">
        <Button
          variant="secondary"
          icon={<Copy aria-hidden="true" size={16} />}
          onClick={() => {
            if (!navigator.clipboard) {
              toast.error(`Couldn't copy the ${label.toLowerCase()}. Select it and copy it manually.`);
              return;
            }
            void navigator.clipboard.writeText(text).then(
              () => toast.success(`${label} copied`),
              () => toast.error(`Couldn't copy the ${label.toLowerCase()}. Select it and copy it manually.`),
            );
          }}
        >
          Copy
        </Button>
        <label htmlFor={checkId} className="secret-panel-ack">
          <input
            id={checkId}
            type="checkbox"
            checked={saved}
            onChange={(event) => setSaved(event.currentTarget.checked)}
          />
          I&apos;ve stored it somewhere safe
        </label>
        <Button disabled={!saved} onClick={onDone}>
          {doneLabel}
        </Button>
      </div>
    </section>
  );
}
