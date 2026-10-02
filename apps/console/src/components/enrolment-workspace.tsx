"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { mintEnrolmentKeyAction, revokeJoinKeyAction } from "@/app/join-keys/actions";
import type { JoinKeySummary } from "@/lib/coord-peers";
import { can, permissionReason, roleLabel, type OrgRole } from "@/lib/roles";
import { EmptyState } from "./empty-state";

type Platform = "linux" | "macos" | "iphone";

function when(value: number | null): string {
  if (!value) return "Never";
  return new Date(value * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

const stateLabel: Record<JoinKeySummary["state"], { label: string; className: string }> = {
  active: { label: "Active", className: "online" },
  expired: { label: "Expired", className: "offline" },
  revoked: { label: "Revoked", className: "revoked" },
  used_up: { label: "Used up", className: "offline" },
};

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
  const [message, setMessage] = useState<{ text: string; error: boolean } | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<JoinKeySummary | null>(null);
  const allowed = can(role, "manage_join_keys");
  const denied = permissionReason(role, "manage_join_keys");
  const coordinator = coordinatorUrl ?? "https://coord.example.org";

  if (!allowed) {
    return (
      <div className="panel">
        <p className="muted">
          {denied} Members can still enrol their own devices with browser
          approval: run <span className="mono">blaktaild up</span> and open the
          link it prints.
        </p>
      </div>
    );
  }

  return (
    <div className="stack">
      <section className="panel stack" aria-labelledby="mint-title">
        <div>
          <h2 id="mint-title">Mint a join key</h2>
          <p className="muted">
            For <span className="badge network">{organisationName}</span> as{" "}
            {roleLabel(role)}. The coordinator stores only a SHA-256 hash; the
            secret is shown once below.
          </p>
        </div>
        <form
          className="stack"
          onSubmit={(event) => {
            event.preventDefault();
            const formData = new FormData(event.currentTarget);
            setMessage(null);
            setMinted(null);
            startTransition(async () => {
              const result = await mintEnrolmentKeyAction(formData);
              if (!result.ok) {
                setMessage({ text: result.error, error: true });
                return;
              }
              setMinted(result.data);
              router.refresh();
            });
          }}
        >
          <input type="hidden" name="organisationId" value={organisationId} />
          <label>
            Name
            <input name="name" type="text" maxLength={64} required placeholder="Ranger tablets, June rollout" />
          </label>
          <label>
            Description (optional)
            <input name="description" type="text" maxLength={200} />
          </label>
          <fieldset className="stack">
            <legend>Uses</legend>
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
            {usageMode === "reusable" ? (
              <label>
                Maximum uses (blank for no limit before expiry)
                <input name="maxUses" type="number" min={1} max={10000} />
              </label>
            ) : null}
          </fieldset>
          <label>
            Expires after
            <select name="expiresInSeconds" defaultValue="3600">
              <option value="900">15 minutes</option>
              <option value="3600">1 hour</option>
              <option value="86400">1 day</option>
              <option value="604800">7 days</option>
              <option value="2592000">30 days</option>
            </select>
          </label>
          <fieldset className="stack">
            <legend>Tags applied to enrolled devices</legend>
            <label>
              <input type="checkbox" name="tags" value="office" /> Office
            </label>
            <label>
              <input type="checkbox" name="tags" value="ranger" /> Ranger
            </label>
            <label>
              <input type="checkbox" name="tags" value="store" /> Store
            </label>
            <p className="muted">
              Tag ownership in the access policy still applies; a key cannot
              grant tags you are not allowed to assign.
            </p>
          </fieldset>
          <button type="submit" disabled={pending}>
            {pending ? "Minting…" : "Mint join key"}
          </button>
        </form>
        {message ? (
          <p className={message.error ? "error" : "muted"} role={message.error ? "alert" : "status"}>
            {message.text}
          </p>
        ) : null}
      </section>

      {minted ? (
        <section className="panel stack" aria-labelledby="minted-title">
          <h2 id="minted-title">Copy “{minted.name}” now</h2>
          <p className="muted">
            This is the only time the secret is shown. It expires {when(minted.expiresAt)}.
            Do not paste it into chat, tickets, URLs or QR codes.
          </p>
          <p className="mono" aria-label="Join key secret">
            {minted.key}
          </p>
          <div className="actions">
            <button
              type="button"
              className="secondary"
              onClick={() => {
                void navigator.clipboard?.writeText(minted.key).then(
                  () => setMessage({ text: "Join key copied.", error: false }),
                  () => setMessage({ text: "Copy failed; select the key and copy it manually.", error: true }),
                );
              }}
            >
              Copy key
            </button>
            <button type="button" className="secondary" onClick={() => setMinted(null)}>
              Hide key
            </button>
          </div>
        </section>
      ) : null}

      <section className="panel stack" aria-labelledby="install-title">
        <h2 id="install-title">Install and enrol</h2>
        <p className="muted">
          Network <span className="badge network">{organisationName}</span> is
          preselected by the key itself. These steps never contain the secret.
          {coordinatorUrl
            ? " If devices reach the coordinator at another address, change --coord."
            : " Replace the example coordinator URL with yours."}
        </p>
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
          <pre className="mono">{instructions(platform, coordinator)}</pre>
        )}
        <p className="muted">
          Build from source: there is no signed release or installer yet.
        </p>
      </section>

      <section className="panel stack" aria-labelledby="inventory-title">
        <h2 id="inventory-title">Keys for {organisationName}</h2>
        {loadError ? (
          <p className="error" role="alert">
            {loadError}
          </p>
        ) : keys.length === 0 ? (
          <EmptyState
            title="No join keys yet"
            body="Keys you mint appear here with their uses, expiry and revoke state. Secrets are never listed."
          />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Key</th>
                  <th>Uses</th>
                  <th>Expiry</th>
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
                      <td>
                        <div className="device-primary">{key.name || "Unnamed key"}</div>
                        <div className="device-sub">
                          {key.description ? `${key.description} · ` : ""}
                          by {key.created_by_role} {key.created_by} · {when(key.created_at)}
                        </div>
                        {key.tags.length > 0 ? (
                          <div>
                            {key.tags.map((tag) => (
                              <span key={tag} className="badge">
                                {tag}
                              </span>
                            ))}
                          </div>
                        ) : null}
                      </td>
                      <td>{usage(key)}</td>
                      <td>{when(key.expires_at)}</td>
                      <td>{when(key.last_used_at)}</td>
                      <td>
                        <span className={`badge ${state.className}`}>{state.label}</span>
                        {key.revoked_at ? <div className="device-sub">{when(key.revoked_at)}</div> : null}
                      </td>
                      <td>
                        {key.state === "active" ? (
                          <button
                            type="button"
                            className="quiet-danger"
                            disabled={pending}
                            onClick={() => setConfirmRevoke(key)}
                          >
                            Revoke
                          </button>
                        ) : null}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </section>

      {confirmRevoke ? (
        <div className="confirm-backdrop">
          <div
            className="confirm-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="revoke-key-title"
            onKeyDown={(event) => {
              if (event.key === "Escape") setConfirmRevoke(null);
            }}
          >
            <h2 id="revoke-key-title">Revoke join key</h2>
            <p>
              Revoke “{confirmRevoke.name || "Unnamed key"}” for {organisationName}?
              No new device can enrol or renew with it. Devices already enrolled
              keep working.
            </p>
            <div className="actions">
              <button type="button" className="secondary" autoFocus onClick={() => setConfirmRevoke(null)}>
                Cancel
              </button>
              <button
                type="button"
                className="danger"
                disabled={pending}
                onClick={() => {
                  const formData = new FormData();
                  formData.set("organisationId", organisationId);
                  formData.set("keyId", confirmRevoke.id);
                  setConfirmRevoke(null);
                  startTransition(async () => {
                    const result = await revokeJoinKeyAction(formData);
                    setMessage({
                      text: result.ok ? "Join key revoked." : result.error,
                      error: !result.ok,
                    });
                    if (result.ok) router.refresh();
                  });
                }}
              >
                Revoke key
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}
