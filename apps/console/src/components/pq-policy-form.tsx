"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { savePqPolicyAction } from "@/app/tunnel-protection/actions";
import type { PqMode, PqPolicy } from "@/lib/coord-pq";
import { Button } from "./ui/button";
import { FormField } from "./ui/form-field";
import { toastResult } from "./ui/toast";

const TAGS = ["office", "ranger", "store"] as const;
const MODE_LABELS: Record<PqMode, string> = {
  off: "Off: classical WireGuard only",
  prefer: "Prefer: use a hybrid key when both devices support it",
  require: "Require: a hybrid key must be established",
};

function TagSelect({ name, defaultValue, none }: { name: string; defaultValue: string; none?: boolean }) {
  return (
    <select name={name} defaultValue={defaultValue}>
      {none ? <option value="">None</option> : null}
      {TAGS.map((tag) => (
        <option key={tag} value={tag}>
          {tag}
        </option>
      ))}
    </select>
  );
}

function ModeSelect({ name, defaultValue }: { name: string; defaultValue: string }) {
  return (
    <select name={name} defaultValue={defaultValue}>
      <option value="off">Off</option>
      <option value="prefer">Prefer</option>
      <option value="require">Require</option>
    </select>
  );
}

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
  const [errors, setErrors] = useState<Record<string, string>>({});
  const locked = pending || disabledReason !== null;

  return (
    <form
      className="ui-form wide"
      noValidate
      onSubmit={(event) => {
        event.preventDefault();
        const form = new FormData(event.currentTarget);
        setErrors({});
        startTransition(async () => {
          const result = await savePqPolicyAction(form);
          setErrors(
            toastResult(result, {
              success: "Tunnel protection saved",
              successDescription: result.ok ? result.message : undefined,
              errorToast: false,
            }),
          );
          if (result.ok) router.refresh();
        });
      }}
    >
      <p className="muted small">
        {disabledReason ? "Viewing" : "Editing"} {organisationName} as {roleLabel.toLowerCase()}.
        Policy revision {policy.revision}
        {policy.updated_by ? `, last changed by ${policy.updated_by}` : ""}.
      </p>
      <input type="hidden" name="revision" value={policy.revision} />
      <input type="hidden" name="rule_count" value={policy.rules.length} />
      <fieldset className="ui-fieldset" disabled={locked}>
        <legend>Default</legend>
        <FormField label="Every device pair" className="field-lg">
          <select name="mode" defaultValue={policy.mode}>
            {(Object.keys(MODE_LABELS) as PqMode[]).map((mode) => (
              <option key={mode} value={mode}>
                {MODE_LABELS[mode]}
              </option>
            ))}
          </select>
        </FormField>
        <label>
          <input
            type="checkbox"
            name="block_unestablished"
            defaultChecked={policy.block_unestablished}
          />
          Under require, block a pair&apos;s traffic (except the key exchange) until a hybrid key
          is established
        </label>
      </fieldset>
      <fieldset className="ui-fieldset" disabled={locked}>
        <legend>Tag-pair rules</legend>
        <p className="ui-field-hint">
          A rule applies to both directions of a pair. When several rules match, the strongest
          wins; when none match, the default applies.
        </p>
        {policy.rules.length === 0 ? (
          <p className="muted small">No tag-pair rules yet.</p>
        ) : null}
        {policy.rules.map((rule, index) => (
          <div className="pq-rule-row" key={`${rule.tags.join("-")}-${index}`}>
            <FormField label="Tag">
              <TagSelect name={`rule_${index}_a`} defaultValue={rule.tags[0]} />
            </FormField>
            <FormField label="With tag">
              <TagSelect name={`rule_${index}_b`} defaultValue={rule.tags[1]} />
            </FormField>
            <FormField label="Mode">
              <ModeSelect name={`rule_${index}_mode`} defaultValue={rule.mode} />
            </FormField>
            <label className="pq-remove">
              <input type="checkbox" name={`rule_${index}_remove`} />
              Remove on save
            </label>
          </div>
        ))}
        <div className="pq-rule-row">
          <FormField label="New rule tag" error={errors.new_a}>
            <TagSelect name="new_a" defaultValue="" none />
          </FormField>
          <FormField label="With tag" error={errors.new_b}>
            <TagSelect name="new_b" defaultValue="" none />
          </FormField>
          <FormField label="Mode">
            <ModeSelect name="new_mode" defaultValue="require" />
          </FormField>
        </div>
      </fieldset>
      {disabledReason ? null : (
        <div className="ui-form-actions">
          <Button type="submit" loading={pending} loadingLabel="Saving…">
            Save post-quantum policy
          </Button>
        </div>
      )}
    </form>
  );
}
