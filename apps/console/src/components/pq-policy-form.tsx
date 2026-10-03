"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { savePqPolicyAction } from "@/app/tunnel-protection/actions";
import type { PqMode, PqPolicy } from "@/lib/coord-pq";

const TAGS = ["office", "ranger", "store"] as const;
const MODE_LABELS: Record<PqMode, string> = {
  off: "Off: classical WireGuard only",
  prefer: "Prefer: use a hybrid key when both devices support it",
  require: "Require: a hybrid key must be established",
};

export function PqPolicyForm({
  policy,
  organisationName,
  roleLabel,
  disabledReason,
}: {
  policy: PqPolicy;
  organisationName: string;
  roleLabel: string;
  disabledReason: string | null;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [notice, setNotice] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const locked = pending || disabledReason !== null;

  return (
    <form
      className="stack"
      onSubmit={(event) => {
        event.preventDefault();
        const form = new FormData(event.currentTarget);
        setError(null);
        setNotice(null);
        startTransition(async () => {
          const result = await savePqPolicyAction(form);
          if (!result.ok) {
            setError(result.error);
            return;
          }
          setNotice(result.message);
          router.refresh();
        });
      }}
    >
      <p className="muted">
        Editing {organisationName} as {roleLabel}. Policy revision {policy.revision}
        {policy.updated_by ? `, last changed by ${policy.updated_by}` : ""}.
      </p>
      <input type="hidden" name="revision" value={policy.revision} />
      <input type="hidden" name="rule_count" value={policy.rules.length} />
      <label>
        Default for every device pair
        <select name="mode" defaultValue={policy.mode} disabled={locked}>
          {(Object.keys(MODE_LABELS) as PqMode[]).map((mode) => (
            <option key={mode} value={mode}>
              {MODE_LABELS[mode]}
            </option>
          ))}
        </select>
      </label>
      <label className="row">
        <input
          type="checkbox"
          name="block_unestablished"
          defaultChecked={policy.block_unestablished}
          disabled={locked}
        />
        Under require, block a pair&apos;s traffic (except the key exchange) until a hybrid key is
        established
      </label>
      <fieldset className="stack" disabled={locked}>
        <legend>Tag-pair rules</legend>
        <p className="muted">
          A rule applies to both directions of a pair. When several rules match, the strongest
          wins; when none match, the default applies.
        </p>
        {policy.rules.map((rule, index) => (
          <div className="row" key={`${rule.tags.join("-")}-${index}`}>
            <label>
              Tag
              <select name={`rule_${index}_a`} defaultValue={rule.tags[0]}>
                {TAGS.map((tag) => (
                  <option key={tag} value={tag}>
                    {tag}
                  </option>
                ))}
              </select>
            </label>
            <label>
              With tag
              <select name={`rule_${index}_b`} defaultValue={rule.tags[1]}>
                {TAGS.map((tag) => (
                  <option key={tag} value={tag}>
                    {tag}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Mode
              <select name={`rule_${index}_mode`} defaultValue={rule.mode}>
                <option value="off">Off</option>
                <option value="prefer">Prefer</option>
                <option value="require">Require</option>
              </select>
            </label>
            <label className="row">
              <input type="checkbox" name={`rule_${index}_remove`} />
              Remove
            </label>
          </div>
        ))}
        <div className="row">
          <label>
            New rule tag
            <select name="new_a" defaultValue="">
              <option value="">None</option>
              {TAGS.map((tag) => (
                <option key={tag} value={tag}>
                  {tag}
                </option>
              ))}
            </select>
          </label>
          <label>
            With tag
            <select name="new_b" defaultValue="">
              <option value="">None</option>
              {TAGS.map((tag) => (
                <option key={tag} value={tag}>
                  {tag}
                </option>
              ))}
            </select>
          </label>
          <label>
            Mode
            <select name="new_mode" defaultValue="require">
              <option value="off">Off</option>
              <option value="prefer">Prefer</option>
              <option value="require">Require</option>
            </select>
          </label>
        </div>
      </fieldset>
      <div className="row">
        <button type="submit" disabled={locked}>
          {pending ? "Saving…" : "Save post-quantum policy"}
        </button>
      </div>
      {disabledReason ? <p className="muted">{disabledReason}</p> : null}
      {notice ? (
        <p className="muted" role="status">
          {notice}
        </p>
      ) : null}
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
    </form>
  );
}
