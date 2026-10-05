"use client";

import { useRouter } from "next/navigation";
import { useMemo, useState, useTransition } from "react";
import { saveAclAction } from "@/app/actions";
import { EmptyState } from "./empty-state";
import { Badge } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { MonoValue } from "./ui/mono-value";
import { Section } from "./ui/section";
import { toastResult } from "./ui/toast";
import {
  ACL_DEFAULTS,
  ACL_PROTOCOLS,
  ACL_ROLES,
  ACL_SSH_ACTIONS,
  ACL_TAGS,
  emptyRule,
  emptySshRule,
  expandGroupMembers,
  memberLabel,
  parseAclPolicy,
  personLabel,
  serializeAclPolicy,
  validGroupName,
  type AclPerson,
  type AclPolicyDraft,
  type AclRuleDraft,
  type AclSshDraft,
} from "@/lib/acl";
import { can, roleLabel, type OrgRole } from "@/lib/roles";

function toggleValue<T extends string>(values: T[], value: T): T[] {
  return values.includes(value)
    ? values.filter((item) => item !== value)
    : [...values, value];
}

function SelectorSet<T extends string>({
  legend,
  values,
  options,
  disabled,
  labelFor,
  emptyHint = "Add a group first if you want to name people here.",
  onChange,
}: {
  legend: string;
  values: T[];
  options: T[];
  disabled: boolean;
  labelFor: (value: T) => string;
  emptyHint?: string;
  onChange: (next: T[]) => void;
}) {
  return (
    <fieldset className="acl-selector" disabled={disabled}>
      <legend>{legend}</legend>
      <div className="acl-options">
        {options.map((option) => (
          <label key={option}>
            <input
              type="checkbox"
              checked={values.includes(option)}
              onChange={() => onChange(toggleValue(values, option))}
            />
            {labelFor(option)}
          </label>
        ))}
        {options.length === 0 ? <p className="muted">{emptyHint}</p> : null}
      </div>
    </fieldset>
  );
}

export function AclEditor({
  initialAcl,
  role,
  people,
  postureChecks = [],
}: {
  initialAcl: string;
  role: OrgRole;
  people: AclPerson[];
  postureChecks?: string[];
}) {
  const router = useRouter();
  const canMutate = can(role, "manage_policy");
  const parsedInitial = useMemo(() => {
    try {
      return parseAclPolicy(JSON.parse(initialAcl) as unknown);
    } catch {
      return parseAclPolicy({ rules: [] });
    }
  }, [initialAcl]);
  const [policy, setPolicy] = useState<AclPolicyDraft>(parsedInitial);
  const [groupName, setGroupName] = useState("");
  const [groupMember, setGroupMember] = useState("");
  const [hostName, setHostName] = useState("");
  const [hostTarget, setHostTarget] = useState("");
  const [groupErrors, setGroupErrors] = useState<{ name?: string; member?: string }>({});
  const [hostErrors, setHostErrors] = useState<{ name?: string; target?: string }>({});
  const [confirmRollback, setConfirmRollback] = useState(false);
  const [pending, startTransition] = useTransition();
  const initialSerialized = useMemo(
    () => JSON.stringify(serializeAclPolicy(parsedInitial)),
    [parsedInitial],
  );
  const dirty = JSON.stringify(serializeAclPolicy(policy)) !== initialSerialized;
  const groupNames = policy.groups.map((group) => group.name);
  // Keep names the policy already references visible even if the check was
  // removed, so a missing check reads as a failing requirement.
  const postureOptions = (selected: string[]) => [
    ...new Set([...postureChecks, ...selected]),
  ];

  function updateRule(index: number, next: AclRuleDraft) {
    setPolicy((current) => ({
      ...current,
      rules: current.rules.map((rule, ruleIndex) =>
        ruleIndex === index ? next : rule,
      ),
    }));
  }

  function updateSsh(index: number, next: AclSshDraft) {
    setPolicy((current) => ({
      ...current,
      ssh: current.ssh.map((rule, ruleIndex) =>
        ruleIndex === index ? next : rule,
      ),
    }));
  }

  return (
    <div className="acl-layout">
      <Section
        id="acl-default"
        title="Default"
        description="What happens to traffic no rule matches. New organisations start with deny; existing documents keep the same-tag compatibility default until you change it."
      >
        <FormField label="Unmatched traffic" className="field-md">
          <select
            data-testid="acl-defaults"
            disabled={!canMutate}
            value={policy.defaults}
            onChange={(event) =>
              setPolicy((current) => ({
                ...current,
                defaults: event.target.value === "deny" ? "deny" : "same_tag",
                generated:
                  event.target.value === "deny" ? [] : current.generated,
              }))
            }
          >
            {ACL_DEFAULTS.map((value) => (
              <option key={value} value={value}>
                {value === "deny"
                  ? "Deny (least privilege)"
                  : "Same tag and untagged (legacy)"}
              </option>
            ))}
          </select>
        </FormField>
        {policy.generated.length > 0 ? (
          <p className="muted" data-testid="acl-generated">
            Visible generated rule: {policy.generated[0]?.note ?? "legacy same-tag allow."}
          </p>
        ) : null}
      </Section>

      <Section
        id="acl-groups"
        title="Groups"
        description="Name a set of people, then use that name in a rule. Members are matched to the account that enrolled each device."
      >
        {policy.groups.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No groups yet"
            body="Create one for a team or site, then use it as a rule source or destination."
          />
        ) : (
          <ul className="acl-group-list">
            {policy.groups.map((group) => (
              <li key={group.name} className="acl-group">
                <div className="acl-group-head">
                  <strong>{group.name}</strong>
                  {canMutate ? (
                    <Button
                      variant="quiet-danger"
                      size="sm"
                      aria-label={`Remove group ${group.name}`}
                      onClick={() =>
                        setPolicy((current) => ({
                          ...current,
                          groups: current.groups.filter(
                            (item) => item.name !== group.name,
                          ),
                          rules: current.rules.map((rule) => ({
                            ...rule,
                            src_groups: rule.src_groups.filter(
                              (name) => name !== group.name,
                            ),
                            dst_groups: rule.dst_groups.filter(
                              (name) => name !== group.name,
                            ),
                          })),
                        }))
                      }
                    >
                      Remove group
                    </Button>
                  ) : null}
                </div>
                <div className="acl-members">
                  {group.members
                    .filter((member, index, members) => {
                      const person = people.find(
                        (candidate) =>
                          candidate.userId === member ||
                          candidate.email.toLowerCase() === member.toLowerCase(),
                      );
                      if (!person) return true;
                      return (
                        members.findIndex(
                          (item) =>
                            item === person.userId ||
                            item.toLowerCase() === person.email.toLowerCase(),
                        ) === index
                      );
                    })
                    .map((member) => (
                      <span key={member} className="badge">
                        {memberLabel(member, people)}
                        {canMutate ? (
                          <button
                            type="button"
                            className="chip-remove"
                            aria-label={`Remove ${memberLabel(member, people)} from ${group.name}`}
                            onClick={() =>
                              setPolicy((current) => ({
                                ...current,
                                groups: current.groups.map((item) =>
                                  item.name === group.name
                                    ? {
                                        ...item,
                                        members: item.members.filter(
                                          (value) => {
                                            const person = people.find(
                                              (candidate) =>
                                                candidate.userId === member ||
                                                candidate.email.toLowerCase() ===
                                                  member.toLowerCase(),
                                            );
                                            if (!person) return value !== member;
                                            return (
                                              value !== person.userId &&
                                              value.toLowerCase() !==
                                                person.email.toLowerCase()
                                            );
                                          },
                                        ),
                                      }
                                    : item,
                                ),
                              }))
                            }
                          >
                            Remove
                          </button>
                        ) : null}
                      </span>
                    ))}
                </div>
                {canMutate ? (
                  <FormField label="Add a person" className="field-md">
                    <select
                      value=""
                      onChange={(event) => {
                        const value = event.target.value;
                        if (!value) return;
                        setPolicy((current) => ({
                          ...current,
                          groups: current.groups.map((item) =>
                            item.name === group.name
                              ? {
                                  ...item,
                                  members: expandGroupMembers(
                                    [...item.members, value],
                                    people,
                                  ),
                                }
                              : item,
                          ),
                        }));
                      }}
                    >
                      <option value="">Choose someone in this organisation</option>
                      {people.map((person) => (
                        <option key={person.userId} value={person.email}>
                          {personLabel(person)}
                        </option>
                      ))}
                    </select>
                  </FormField>
                ) : null}
              </li>
            ))}
          </ul>
        )}
        {canMutate ? (
          <form
            className="acl-add-group"
            onSubmit={(event) => {
              event.preventDefault();
              const name = groupName.trim().toLowerCase();
              const member = groupMember.trim();
              if (!validGroupName(name)) {
                setGroupErrors({
                  name: "Start with a lowercase letter, then use letters, digits or hyphens.",
                });
                return;
              }
              if (policy.groups.some((group) => group.name === name)) {
                setGroupErrors({ name: "That group name is already in use." });
                return;
              }
              if (!member) {
                setGroupErrors({ member: "Choose the first person for this group." });
                return;
              }
              setGroupErrors({});
              setPolicy((current) => ({
                ...current,
                groups: [
                  ...current.groups,
                  { name, members: expandGroupMembers([member], people) },
                ],
              }));
              setGroupName("");
              setGroupMember("");
            }}
          >
            <FormField label="New group name" error={groupErrors.name}>
              <input
                name="group-name"
                value={groupName}
                onChange={(event) => setGroupName(event.target.value)}
                placeholder="rangers"
                autoComplete="off"
                maxLength={64}
              />
            </FormField>
            <FormField label="First person" error={groupErrors.member}>
              <select
                name="group-member"
                value={groupMember}
                onChange={(event) => setGroupMember(event.target.value)}
              >
                <option value="">Choose someone</option>
                {people.map((person) => (
                  <option key={person.userId} value={person.email}>
                    {personLabel(person)}
                  </option>
                ))}
              </select>
            </FormField>
            <Button type="submit" variant="secondary" data-testid="acl-add-group">
              Add group
            </Button>
          </form>
        ) : null}
      </Section>

      <Section
        id="acl-hosts"
        title="Hosts"
        description="Name a private address or subnet, then use that name as a rule destination. Packet-level enforcement of host-only rules is still to come; tests can already assert them."
      >
        {policy.hosts.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No named hosts yet"
            body="Add one, such as wiki at 10.0.0.10, to use it as a rule destination."
          />
        ) : (
          <ul className="acl-group-list">
            {policy.hosts.map((host) => (
              <li key={host.name} className="acl-group">
                <div className="acl-group-head">
                  <strong>{host.name}</strong>
                  <MonoValue value={host.target} />
                  {canMutate ? (
                    <Button
                      variant="quiet-danger"
                      size="sm"
                      aria-label={`Remove host ${host.name}`}
                      onClick={() =>
                        setPolicy((current) => ({
                          ...current,
                          hosts: current.hosts.filter((item) => item.name !== host.name),
                          rules: current.rules.map((rule) => ({
                            ...rule,
                            dst_hosts: rule.dst_hosts.filter((name) => name !== host.name),
                          })),
                        }))
                      }
                    >
                      Remove host
                    </Button>
                  ) : null}
                </div>
              </li>
            ))}
          </ul>
        )}
        {canMutate ? (
          <form
            className="acl-add-group"
            onSubmit={(event) => {
              event.preventDefault();
              const name = hostName.trim().toLowerCase();
              const target = hostTarget.trim();
              if (!validGroupName(name)) {
                setHostErrors({
                  name: "Start with a lowercase letter, then use letters, digits or hyphens.",
                });
                return;
              }
              if (policy.hosts.some((host) => host.name === name)) {
                setHostErrors({ name: "That host name is already in use." });
                return;
              }
              if (!target) {
                setHostErrors({ target: "Enter a private address or CIDR, such as 10.0.0.10." });
                return;
              }
              setHostErrors({});
              setPolicy((current) => ({
                ...current,
                hosts: [...current.hosts, { name, target }],
              }));
              setHostName("");
              setHostTarget("");
            }}
          >
            <FormField label="New host name" error={hostErrors.name}>
              <input
                name="host-name"
                value={hostName}
                onChange={(event) => setHostName(event.target.value)}
                placeholder="wiki"
                autoComplete="off"
                maxLength={64}
              />
            </FormField>
            <FormField label="Address or CIDR" error={hostErrors.target}>
              <input
                name="host-target"
                className="mono"
                value={hostTarget}
                onChange={(event) => setHostTarget(event.target.value)}
                placeholder="10.0.0.10"
                autoComplete="off"
                spellCheck={false}
              />
            </FormField>
            <Button type="submit" variant="secondary" data-testid="acl-add-host">
              Add host
            </Button>
          </form>
        ) : null}
      </Section>

      <Section
        id="acl-rules"
        title="Rules"
        description="Explicit deny wins. A blank source or destination matches everyone on that side. Tagged devices still default to the same tag unless a rule says otherwise."
        actions={
          policy.rules.length > 0 ? (
            <Badge dot={false}>
              {policy.rules.length} {policy.rules.length === 1 ? "rule" : "rules"}
            </Badge>
          ) : null
        }
      >
        {policy.rules.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No extra rules"
            body={
              policy.defaults === "deny"
                ? "Nothing is allowed until you add an allow rule."
                : "Same-tag devices can already reach each other. Add a rule to allow or deny more."
            }
          />
        ) : (
          <ol className="acl-rule-list">
            {policy.rules.map((rule, index) => (
              <li key={index} id={`rule-${index + 1}`} className="acl-rule">
                <div className="acl-rule-head">
                  <h3 className="acl-rule-title">Rule {index + 1}</h3>
                  <label className="acl-action">
                    Action
                    <select
                      value={rule.action}
                      disabled={!canMutate}
                      onChange={(event) =>
                        updateRule(index, {
                          ...rule,
                          action: event.target.value === "deny" ? "deny" : "allow",
                        })
                      }
                    >
                      <option value="allow">Allow</option>
                      <option value="deny">Deny</option>
                    </select>
                  </label>
                  {canMutate ? (
                    <Button
                      variant="quiet-danger"
                      size="sm"
                      aria-label={`Remove rule ${index + 1}`}
                      onClick={() =>
                        setPolicy((current) => ({
                          ...current,
                          rules: current.rules.filter(
                            (_, ruleIndex) => ruleIndex !== index,
                          ),
                        }))
                      }
                    >
                      Remove rule
                    </Button>
                  ) : null}
                </div>
                <div className="acl-rule-grid">
                  <SelectorSet
                    legend="From roles"
                    values={rule.src_roles}
                    options={ACL_ROLES}
                    disabled={!canMutate}
                    labelFor={roleLabel}
                    onChange={(src_roles) => updateRule(index, { ...rule, src_roles })}
                  />
                  <SelectorSet
                    legend="From tags"
                    values={rule.src_tags}
                    options={ACL_TAGS}
                    disabled={!canMutate}
                    labelFor={(tag) => tag}
                    onChange={(src_tags) => updateRule(index, { ...rule, src_tags })}
                  />
                  <SelectorSet
                    legend="From groups"
                    values={rule.src_groups}
                    options={groupNames}
                    disabled={!canMutate}
                    labelFor={(name) => name}
                    onChange={(src_groups) =>
                      updateRule(index, { ...rule, src_groups })
                    }
                  />
                  <SelectorSet
                    legend="To roles"
                    values={rule.dst_roles}
                    options={ACL_ROLES}
                    disabled={!canMutate}
                    labelFor={roleLabel}
                    onChange={(dst_roles) => updateRule(index, { ...rule, dst_roles })}
                  />
                  <SelectorSet
                    legend="To tags"
                    values={rule.dst_tags}
                    options={ACL_TAGS}
                    disabled={!canMutate}
                    labelFor={(tag) => tag}
                    onChange={(dst_tags) => updateRule(index, { ...rule, dst_tags })}
                  />
                  <SelectorSet
                    legend="To groups"
                    values={rule.dst_groups}
                    options={groupNames}
                    disabled={!canMutate}
                    labelFor={(name) => name}
                    onChange={(dst_groups) =>
                      updateRule(index, { ...rule, dst_groups })
                    }
                  />
                  <SelectorSet
                    legend="To hosts"
                    values={rule.dst_hosts}
                    options={policy.hosts.map((host) => host.name)}
                    disabled={!canMutate}
                    labelFor={(name) => name}
                    emptyHint="Add a host first if you want to name it here."
                    onChange={(dst_hosts) =>
                      updateRule(index, { ...rule, dst_hosts })
                    }
                  />
                  <SelectorSet
                    legend="Protocols"
                    values={rule.protocols}
                    options={[...ACL_PROTOCOLS]}
                    disabled={!canMutate}
                    labelFor={(protocol) => protocol.toUpperCase()}
                    onChange={(protocols) =>
                      updateRule(index, { ...rule, protocols })
                    }
                  />
                  <label className="acl-selector">
                    <span className="acl-selector-label">Destination ports</span>
                    <input
                      className="mono"
                      value={rule.dst_ports.join(",")}
                      disabled={!canMutate}
                      placeholder="22,80-443"
                      onChange={(event) =>
                        updateRule(index, {
                          ...rule,
                          dst_ports: event.target.value
                            .split(",")
                            .map((item) => item.trim())
                            .filter(Boolean),
                        })
                      }
                    />
                  </label>
                  {rule.action === "allow" ? (
                    <SelectorSet
                      legend="Source must pass posture"
                      values={rule.posture}
                      options={postureOptions(rule.posture)}
                      disabled={!canMutate}
                      labelFor={(name) => name}
                      emptyHint="No posture checks yet. Create one under Posture checks."
                      onChange={(posture) => updateRule(index, { ...rule, posture })}
                    />
                  ) : null}
                </div>
              </li>
            ))}
          </ol>
        )}
        {canMutate ? (
          <div className="ui-form-actions">
            <Button
              variant="secondary"
              data-testid="acl-add-rule"
              onClick={() =>
                setPolicy((current) => ({
                  ...current,
                  rules: [...current.rules, emptyRule()],
                }))
              }
            >
              Add rule
            </Button>
          </div>
        ) : null}
      </Section>

      <Section
        id="acl-ssh"
        title="SSH"
        description="Decide which operating-system users a source may open on a destination. SSH rules govern TCP 22 on every destination they select: sources without an SSH grant are rejected there even if a port rule allows 22."
      >
        <div>
          <ul className="audit-details" aria-label="Where SSH rules are enforced">
            <li>
              <span className="badge online">Linux agent</span> Rejects TCP 22
              from sources without a grant.
            </li>
            <li>
              <span className="badge online">Linux agent with ssh-users</span>{" "}
              Also limits logins per source through a verified sshd drop-in.
              Without it, user-limited grants keep TCP 22 closed.
            </li>
            <li>
              <span className="badge pending">macOS, Windows, iOS and Android</span>{" "}
              Agents that report the inbound filter reject TCP 22 from sources
              without a grant and keep it closed for user-limited grants;
              per-user limits are Linux-only. Older clients do not filter. Use
              Explain access to check a specific device.
            </li>
          </ul>
        </div>
        {policy.ssh.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No SSH rules yet"
            body="Without SSH rules, port rules alone decide who reaches TCP 22."
          />
        ) : (
          <ol className="acl-rule-list">
            {policy.ssh.map((rule, index) => (
              <li key={`ssh-${index}`} className="acl-rule">
                <div className="acl-rule-head">
                  <h3 className="acl-rule-title">SSH rule {index + 1}</h3>
                  <label className="acl-action">
                    Action
                    <select
                      value={rule.action}
                      disabled={!canMutate}
                      onChange={(event) =>
                        updateSsh(index, {
                          ...rule,
                          action: event.target.value as AclSshDraft["action"],
                        })
                      }
                    >
                      {ACL_SSH_ACTIONS.map((action) => (
                        <option key={action} value={action}>
                          {action === "check" ? "check (recent credential renewal)" : action}
                        </option>
                      ))}
                    </select>
                  </label>
                  {canMutate ? (
                    <Button
                      variant="quiet-danger"
                      size="sm"
                      aria-label={`Remove SSH rule ${index + 1}`}
                      onClick={() =>
                        setPolicy((current) => ({
                          ...current,
                          ssh: current.ssh.filter(
                            (_, ruleIndex) => ruleIndex !== index,
                          ),
                        }))
                      }
                    >
                      Remove SSH rule
                    </Button>
                  ) : null}
                </div>
                <div className="acl-rule-grid">
                  <SelectorSet
                    legend="From roles"
                    values={rule.src_roles}
                    options={ACL_ROLES}
                    disabled={!canMutate}
                    labelFor={roleLabel}
                    onChange={(src_roles) => updateSsh(index, { ...rule, src_roles })}
                  />
                  <SelectorSet
                    legend="From tags"
                    values={rule.src_tags}
                    options={ACL_TAGS}
                    disabled={!canMutate}
                    labelFor={(tag) => tag}
                    onChange={(src_tags) => updateSsh(index, { ...rule, src_tags })}
                  />
                  <SelectorSet
                    legend="From groups"
                    values={rule.src_groups}
                    options={groupNames}
                    disabled={!canMutate}
                    labelFor={(name) => name}
                    onChange={(src_groups) =>
                      updateSsh(index, { ...rule, src_groups })
                    }
                  />
                  <SelectorSet
                    legend="To roles"
                    values={rule.dst_roles}
                    options={ACL_ROLES}
                    disabled={!canMutate}
                    labelFor={roleLabel}
                    onChange={(dst_roles) => updateSsh(index, { ...rule, dst_roles })}
                  />
                  <SelectorSet
                    legend="To tags"
                    values={rule.dst_tags}
                    options={ACL_TAGS}
                    disabled={!canMutate}
                    labelFor={(tag) => tag}
                    onChange={(dst_tags) => updateSsh(index, { ...rule, dst_tags })}
                  />
                  <SelectorSet
                    legend="To groups"
                    values={rule.dst_groups}
                    options={groupNames}
                    disabled={!canMutate}
                    labelFor={(name) => name}
                    onChange={(dst_groups) =>
                      updateSsh(index, { ...rule, dst_groups })
                    }
                  />
                  <label className="acl-selector">
                    <span className="acl-selector-label">Operating-system users</span>
                    <input
                      className="mono"
                      value={rule.users.join(",")}
                      disabled={!canMutate}
                      placeholder="ubuntu,deploy,*"
                      onChange={(event) =>
                        updateSsh(index, {
                          ...rule,
                          users: event.target.value
                            .split(",")
                            .map((item) => item.trim())
                            .filter(Boolean),
                        })
                      }
                    />
                  </label>
                  {rule.action !== "deny" ? (
                    <SelectorSet
                      legend="Source must pass posture"
                      values={rule.posture}
                      options={postureOptions(rule.posture)}
                      disabled={!canMutate}
                      labelFor={(name) => name}
                      emptyHint="No posture checks yet. Create one under Posture checks."
                      onChange={(posture) => updateSsh(index, { ...rule, posture })}
                    />
                  ) : null}
                  {rule.action === "check" ? (
                    <label className="acl-selector">
                      <span className="acl-selector-label">Check period (seconds)</span>
                      <span className="ui-field-hint">
                        The source device&apos;s credential must have been
                        renewed within it; this is not an interactive person
                        re-authentication. Default 43200.
                      </span>
                      <input
                        inputMode="numeric"
                        value={rule.check_period_secs}
                        disabled={!canMutate}
                        placeholder="3600"
                        onChange={(event) =>
                          updateSsh(index, {
                            ...rule,
                            check_period_secs: event.target.value,
                          })
                        }
                      />
                    </label>
                  ) : null}
                </div>
              </li>
            ))}
          </ol>
        )}
        {canMutate ? (
          <div className="ui-form-actions">
            <Button
              variant="secondary"
              data-testid="acl-add-ssh"
              onClick={() =>
                setPolicy((current) => ({
                  ...current,
                  ssh: [...current.ssh, emptySshRule()],
                }))
              }
            >
              Add SSH rule
            </Button>
          </div>
        ) : null}
      </Section>

      <Section
        id="acl-publish"
        title={canMutate ? "Publish" : "Published policy"}
        description={
          canMutate
            ? "Changes above stay in this browser until you save. Saving publishes the policy to every device in this organisation."
            : "The policy as published on the coordinator."
        }
        actions={
          canMutate ? (
            dirty ? (
              <Badge tone="warning">Unsaved changes</Badge>
            ) : (
              <Badge tone="muted">No unsaved changes</Badge>
            )
          ) : null
        }
      >
      {canMutate ? (
        <div className="ui-form-actions">
          <Button
            data-testid="acl-save"
            loading={pending}
            loadingLabel="Saving…"
            onClick={() => {
              const formData = new FormData();
              formData.set(
                "aclJson",
                JSON.stringify(serializeAclPolicy(policy), null, 2),
              );
              formData.set("etag", policy.etag);
              startTransition(async () => {
                const result = await saveAclAction(formData);
                toastResult(result, {
                  success: "Access policy published",
                  successDescription: "Access policy saved on the coordinator.",
                });
                if (result.ok) {
                  router.refresh();
                }
              });
            }}
          >
            Save access policy
          </Button>
          {policy.has_previous ? (
            <Button
              variant="secondary"
              data-testid="acl-rollback"
              disabled={pending}
              onClick={() => setConfirmRollback(true)}
            >
              Roll back
            </Button>
          ) : null}
        </div>
      ) : null}

      <details className="acl-advanced">
        <summary>Advanced JSON</summary>
        <pre className="mono">{JSON.stringify(serializeAclPolicy(policy), null, 2)}</pre>
      </details>
      </Section>

      <ConfirmDialog
        open={confirmRollback}
        title="Roll back access policy"
        description="The previous published policy replaces the current one on every device straight away. Unsaved edits on this page are discarded."
        confirmLabel="Roll back policy"
        pending={pending}
        onCancel={() => setConfirmRollback(false)}
        onConfirm={() => {
          const formData = new FormData();
          formData.set("rollback", "true");
          formData.set("etag", policy.etag);
          startTransition(async () => {
            const result = await saveAclAction(formData);
            toastResult(result, {
              success: "Access policy rolled back",
              successDescription: "The previous policy is live on the coordinator again.",
            });
            setConfirmRollback(false);
            if (result.ok) {
              router.refresh();
            }
          });
        }}
      />
    </div>
  );
}
