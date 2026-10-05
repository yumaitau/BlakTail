"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { mintEnrolmentKeyAction, revokeJoinKeyAction } from "@/app/join-keys/actions";
import { Alert } from "./ui/alert";
import { Badge, StatusPill, type BadgeTone } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { CopyButton } from "./ui/copy-button";
import { FormField } from "./ui/form-field";
import { LocalTime } from "./ui/local-time";
import { PermissionNotice } from "./ui/permission-notice";
import { Section } from "./ui/section";
import { Table, Td } from "./ui/table";
import { toastResult } from "./ui/toast";
import type { JoinKeySummary } from "@/lib/coord-peers";
import { can, isOrgRole, permissionReason, roleLabel, type OrgRole } from "@/lib/roles";
import { EmptyState } from "./empty-state";

type Platform = "linux" | "macos" | "iphone";

const stateLabel: Record<JoinKeySummary["state"], { label: string; tone: BadgeTone }> = {
  active: { label: "Active", tone: "success" },
  expired: { label: "Expired", tone: "muted" },
  revoked: { label: "Revoked", tone: "danger" },
  used_up: { label: "Used up", tone: "muted" },
};

function creator(key: JoinKeySummary) {
  const role = isOrgRole(key.created_by_role) ? roleLabel(key.created_by_role) : key.created_by_role;
  return (
    <>
      Minted by {role ? role.toLowerCase() : "someone"} · <LocalTime value={key.created_at} />
    </>
  );
}

function usage(key: JoinKeySummary): string {
  if (key.single_use) return key.use_count > 0 ? "One-use · used" : "One-use · unused";
  if (key.max_uses === null) return `Reusable · ${key.use_count} used · no limit`;
  return `Reusable · ${key.use_count} of ${key.max_uses} used · ${key.remaining_uses ?? 0} left`;
}

/**
 * Install steps never contain the secret: the operator pastes it into a
 * hidden `read` prompt, and the agent receives it on stdin. Nothing lands in
 * argv, shell history, URLs or QR codes.
 */
function instructions(platform: Platform, coordinatorUrl: string): string {
  const build = [
    "# No signed release exists yet: build from source.",
    "git clone https://github.com/jusso-dev/BlakTail.git && cd BlakTail",
    "cargo build --locked --release -p blaktaild",
    "sudo install -m 0755 target/release/blaktaild /usr/local/bin/blaktaild",
  ];
  const enrol = [
    "# Paste the join key at the prompt; it is not echoed or saved to history.",
    "read -rs BLAKTAIL_JOIN_KEY",
    `printf '%s' "$BLAKTAIL_JOIN_KEY" | sudo /usr/local/bin/blaktaild up --coord ${coordinatorUrl} --exit-after-join`,
    "unset BLAKTAIL_JOIN_KEY",
    "sudo /usr/local/bin/blaktaild status",
  ];
  if (platform === "linux") {
    return [
      "# Linux: needs iproute2, wireguard-tools and iptables.",
      ...build,
      ...enrol,
      "# Then enable the systemd unit from packaging/ (see docs/linux-agent.md).",
    ].join("\n");
  }
  return [
    "# macOS 14+: needs Xcode command line tools and Rust.",
    ...build,
    ...enrol,
    "# Then load the LaunchDaemon (see docs/macos-agent.md).",
  ].join("\n");
}

export function EnrolmentWorkspace({
  keys,
  loadError,
  organisationId,
  organisationName,
  role,
  coordinatorUrl,
}: {
  keys: JoinKeySummary[];
  loadError: string | null;
  organisationId: string;
  organisationName: string;
  role: OrgRole;
  coordinatorUrl: string | null;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [usageMode, setUsageMode] = useState<"single" | "reusable">("single");
  const [minted, setMinted] = useState<{ key: string; name: string; expiresAt: number } | null>(null);
  const [platform, setPlatform] = useState<Platform>("linux");
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [confirmRevoke, setConfirmRevoke] = useState<JoinKeySummary | null>(null);
  const allowed = can(role, "manage_join_keys");
  const denied = permissionReason(role, "manage_join_keys");
  const coordinator = coordinatorUrl ?? "https://coord.example.org";

  if (!allowed) {
    return (
      <PermissionNotice reason={denied ?? "Your role cannot manage join keys."}>
        You can still enrol your own devices with browser approval: run{" "}
        <span className="mono nowrap">blaktaild up</span> and open the link it prints.
      </PermissionNotice>
    );
  }

  return (
    <div className="stack">
      <Section
        id="mint"
        title="Mint a join key"
        description={
          <>
            For <Badge tone="brand">{organisationName}</Badge> as {roleLabel(role)}. The
            coordinator stores only a hash; the secret is shown once.
          </>
        }
      >
        <form
          className="ui-form"
          noValidate
          onSubmit={(event) => {
            event.preventDefault();
            const formData = new FormData(event.currentTarget);
            setFieldErrors({});
            setMinted(null);
            startTransition(async () => {
              const result = await mintEnrolmentKeyAction(formData);
              setFieldErrors(
                toastResult(result, {
                  success: "Join key minted",
                  successDescription: "Copy it now. It's shown only once.",
                  errorToast: false,
                }),
              );
              if (!result.ok) return;
              setMinted(result.data);
              router.refresh();
            });
          }}
        >
          <input type="hidden" name="organisationId" value={organisationId} />
          <FormField label="Name" required error={fieldErrors.name} className="field-md">
            <input name="name" type="text" maxLength={64} placeholder="Ranger tablets, June rollout" />
          </FormField>
          <FormField
            label="Description"
            hint="Optional. Who or what the key is for."
            error={fieldErrors.description}
            className="field-lg"
          >
            <input name="description" type="text" maxLength={200} />
          </FormField>
          <fieldset className="ui-fieldset">
            <legend>Uses</legend>
            <div className="ui-choices">
              <label>
                <input
                  type="radio"
                  name="usage"
                  value="single"
                  checked={usageMode === "single"}
                  onChange={() => setUsageMode("single")}
                />{" "}
                One device (one-use)
              </label>
              <label>
                <input
                  type="radio"
                  name="usage"
                  value="reusable"
                  checked={usageMode === "reusable"}
                  onChange={() => setUsageMode("reusable")}
                />{" "}
                Several devices (reusable)
              </label>
            </div>
            {usageMode === "reusable" ? (
              <FormField
                label="Maximum uses"
                hint="Leave blank for no limit before the key expires."
                error={fieldErrors.maxUses}
                className="field-sm"
              >
                <input name="maxUses" type="number" min={1} max={10000} />
              </FormField>
            ) : null}
          </fieldset>
          <FormField label="Expires after" className="field-sm">
            <select name="expiresInSeconds" defaultValue="3600">
              <option value="900">15 minutes</option>
              <option value="3600">1 hour</option>
              <option value="86400">1 day</option>
              <option value="604800">7 days</option>
              <option value="2592000">30 days</option>
            </select>
          </FormField>
          <fieldset className="ui-fieldset">
            <legend>Tags applied to enrolled devices</legend>
            <div className="ui-choices">
              <label>
                <input type="checkbox" name="tags" value="office" /> Office
              </label>
              <label>
                <input type="checkbox" name="tags" value="ranger" /> Ranger
              </label>
              <label>
                <input type="checkbox" name="tags" value="store" /> Store
              </label>
            </div>
            <p className="ui-field-hint">
              Tag ownership in the access policy still applies; a key cannot
              grant tags you are not allowed to assign.
            </p>
          </fieldset>
          <div className="ui-form-actions">
            <Button type="submit" loading={pending && !confirmRevoke} disabled={pending} loadingLabel="Minting…">
              Mint join key
            </Button>
          </div>
        </form>
      </Section>

      {minted ? (
        <Section
          id="minted"
          title={`Copy “${minted.name}” now`}
          description={
            <>
              This is the only time the secret is shown. It expires <LocalTime value={minted.expiresAt} />. Don&apos;t
              paste it into chat, tickets, URLs or QR codes.
            </>
          }
          className="secret-panel"
        >
          <div className="secret-value">
            <code className="mono" aria-label="Join key secret">
              {minted.key}
            </code>
            <CopyButton value={minted.key} label="Copy join key" toastMessage="Join key copied" />
          </div>
          <div className="actions">
            <Button variant="secondary" onClick={() => setMinted(null)}>
              I&apos;ve saved it, hide the key
            </Button>
          </div>
        </Section>
      ) : null}

      <Section
        id="install"
        title="Install and enrol"
        description={
          <>
            Network <Badge tone="brand">{organisationName}</Badge> is preselected by the key
            itself. These steps never contain the secret.
            {coordinatorUrl ? (
              <>
                {" "}
                If devices reach the coordinator at another address, change{" "}
                <span className="mono nowrap">--coord</span>.
              </>
            ) : (
              " Replace the example coordinator URL with yours."
            )}
          </>
        }
      >
        <div className="filter-row" role="group" aria-label="Platform">
          {(
            [
              ["linux", "Linux"],
              ["macos", "macOS"],
              ["iphone", "iPhone"],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              type="button"
              className={platform === value ? "filter-chip active" : "filter-chip"}
              aria-pressed={platform === value}
              onClick={() => setPlatform(value)}
            >
              {label}
            </button>
          ))}
        </div>
        {platform === "iphone" ? (
          <p className="muted">
            iPhone does not use pasted join keys. Build the app from source (see
            docs/ios.md), sign in, choose {organisationName}, and the app mints
            its own one-use key over the console session.
          </p>
        ) : (
          <div className="code-block">
            <pre className="mono">{instructions(platform, coordinator)}</pre>
            <CopyButton
              value={instructions(platform, coordinator)}
              label="Copy install steps"
              toastMessage="Install steps copied"
            />
          </div>
        )}
        <p className="muted">
          Build from source: there is no signed release or installer yet.
        </p>
      </Section>

      <Section id="keys" title={`Keys for ${organisationName}`}>
        {loadError ? (
          <Alert tone="error" title="Couldn't load join keys">
            {loadError}
          </Alert>
        ) : keys.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No join keys yet"
            body="Keys you mint appear here with their uses, expiry and state. Secrets are never listed."
          />
        ) : (
          <Table label={`Join keys for ${organisationName}`} mobile="stack">
            <thead>
              <tr>
                <th>Key</th>
                <th>Uses</th>
                <th>Expires</th>
                <th>Last used</th>
                <th>Status</th>
                <th>
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {keys.map((key) => {
                const state = stateLabel[key.state];
                return (
                  <tr key={key.id}>
                    <Td label="Key">
                      <div>
                        <div className="device-primary">{key.name || "Unnamed key"}</div>
                        {key.description ? (
                          <div className="cell-sub truncate" title={key.description}>
                            {key.description}
                          </div>
                        ) : null}
                        <div className="cell-sub">{creator(key)}</div>
                        {key.tags.length > 0 ? (
                          <div className="tag-list">
                            {key.tags.map((tag) => (
                              <Badge key={tag}>{tag}</Badge>
                            ))}
                          </div>
                        ) : null}
                      </div>
                    </Td>
                    <Td label="Uses">{usage(key)}</Td>
                    <Td label="Expires">
                      <LocalTime value={key.expires_at} />
                    </Td>
                    <Td label="Last used">
                      <LocalTime value={key.last_used_at} />
                    </Td>
                    <Td label="Status">
                      <div>
                        <StatusPill tone={state.tone}>{state.label}</StatusPill>
                        {key.revoked_at ? (
                          <div className="cell-sub">
                            <LocalTime value={key.revoked_at} />
                          </div>
                        ) : null}
                      </div>
                    </Td>
                    <Td>
                      {key.state === "active" ? (
                        <div className="cell-actions">
                          <Button
                            size="sm"
                            variant="quiet-danger"
                            disabled={pending}
                            onClick={() => setConfirmRevoke(key)}
                          >
                            Revoke
                          </Button>
                        </div>
                      ) : null}
                    </Td>
                  </tr>
                );
              })}
            </tbody>
          </Table>
        )}
      </Section>

      <ConfirmDialog
        open={confirmRevoke !== null}
        title="Revoke join key"
        description={
          confirmRevoke
            ? `No new device can enrol or renew with “${confirmRevoke.name || "Unnamed key"}” for ${organisationName}. Devices already enrolled keep working.`
            : null
        }
        confirmLabel="Revoke key"
        confirmText={confirmRevoke ? confirmRevoke.name || "Unnamed key" : undefined}
        pending={pending}
        onCancel={() => setConfirmRevoke(null)}
        onConfirm={() => {
          if (!confirmRevoke) return;
          const formData = new FormData();
          formData.set("organisationId", organisationId);
          formData.set("keyId", confirmRevoke.id);
          startTransition(async () => {
            const result = await revokeJoinKeyAction(formData);
            toastResult(result, { success: "Join key revoked" });
            setConfirmRevoke(null);
            if (result.ok) router.refresh();
          });
        }}
      />
    </div>
  );
}
