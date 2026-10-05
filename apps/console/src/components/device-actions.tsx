"use client";

import { useMemo, useState, useTransition } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  approveNodeRoutesAction,
  revokeDeviceAction,
  tombstoneDeviceAction,
  updateDeviceFriendlyNameAction,
} from "@/app/actions";
import type { AclPerson } from "@/lib/acl";
import type { NetworkNode } from "@/lib/coord";
import { can, isOrgRole, roleLabel } from "@/lib/roles";
import { EmptyState } from "./empty-state";
import { Badge, StatusPill, type BadgeTone } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { MonoValue } from "./ui/mono-value";
import { Table } from "./ui/table";
import { toastResult } from "./ui/toast";

type StatusFilter = "all" | "online" | "offline" | "attention";

function nodeLabel(node: NetworkNode): string {
  return node.display_name || node.name;
}

function nodeState(node: NetworkNode): {
  label: string;
  tone: BadgeTone;
} {
  if (node.deleted) return { label: "Deleted", tone: "danger" };
  if (node.revoked) return { label: "Revoked", tone: "danger" };
  if (node.suspended) return { label: "Suspended", tone: "warning" };
  if (node.expired) return { label: "Expired", tone: "danger" };
  if (node.expires_soon) return { label: "Expires soon", tone: "warning" };
  if (node.online) return { label: "Online", tone: "success" };
  return { label: "Offline", tone: "muted" };
}

function needsAttention(node: NetworkNode): boolean {
  return (
    !node.deleted &&
    (node.revoked ||
      node.suspended ||
      node.expired ||
      node.expires_soon ||
      node.advertised_routes.some((route) => !node.approved_routes.includes(route)))
  );
}

function formatSeen(value: number | null | undefined): string {
  if (!value) return "Never";
  return new Date(value * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

function ownerLabel(node: NetworkNode, people: AclPerson[]): string {
  const person = people.find((candidate) => candidate.userId === node.user_id);
  if (person) return person.name || person.email;
  // Devices enrolled by a key or a service user have no person; name the role.
  return isOrgRole(node.user_role) ? `Enrolled by ${roleLabel(node.user_role).toLowerCase()}` : node.user_role;
}

export function DeviceActions({
  nodes,
  people,
  loadFailed = false,
}: {
  nodes: NetworkNode[];
  people: AclPerson[];
  /** Some networks failed to load: don't claim there are no devices. */
  loadFailed?: boolean;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<StatusFilter>("all");
  const [openId, setOpenId] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<{
    kind: "revoke" | "delete";
    node: NetworkNode;
  } | null>(null);

  const visible = useMemo(() => {
    const wanted = query.trim().toLowerCase();
    return nodes.filter((node) => {
      if (filter === "online" && !(node.online && !node.revoked && !node.deleted)) {
        return false;
      }
      if (filter === "offline" && (node.online || node.revoked || node.deleted)) {
        return false;
      }
      if (filter === "attention" && !needsAttention(node)) return false;
      if (!wanted) return true;
      return [
        node.name,
        node.display_name ?? "",
        node.dns_name,
        node.hostname ?? "",
        node.os ?? "",
        node.network_account_name,
        node.organisation_name,
        node.id,
        ownerLabel(node, people),
        ...(node.shares ?? []).map((share) => share.label),
      ]
        .join(" ")
        .toLowerCase()
        .includes(wanted);
    });
  }, [filter, nodes, people, query]);

  // The page already shows why loading failed; an empty state would mislead.
  if (nodes.length === 0 && loadFailed) return null;

  if (nodes.length === 0) {
    return (
      <EmptyState
        title="No devices yet"
        body="Bring your first device onto this network with a join key, or run blaktaild up on it and approve it in the browser."
        action={
          <Link className="button" href="/join-keys">
            Mint a join key
          </Link>
        }
      />
    );
  }

  return (
    <div className="stack">
      <div className="ui-toolbar">
        <FormField label="Search devices">
          <input
            type="search"
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Name, DNS, network or person"
          />
        </FormField>
        <div className="filter-row" role="group" aria-label="Device status">
          {(
            [
              ["all", "All"],
              ["online", "Online"],
              ["offline", "Offline"],
              ["attention", "Needs attention"],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              type="button"
              className={filter === value ? "filter-chip active" : "filter-chip"}
              aria-pressed={filter === value}
              onClick={() => setFilter(value)}
            >
              {label}
            </button>
          ))}
        </div>
      </div>
      {visible.length === 0 ? (
        <EmptyState
          compact
          headingLevel={3}
          title="No devices match"
          body="Try another name or address, or show every device."
          action={
            <Button
              variant="secondary"
              onClick={() => {
                setQuery("");
                setFilter("all");
              }}
            >
              Clear search and filters
            </Button>
          }
        />
      ) : (
        <Table label="Devices" className="device-table">
            <thead>
              <tr>
                <th>Device</th>
                <th>Network</th>
                <th>Address</th>
                <th>Status</th>
                <th>
                  <span className="visually-hidden">Details</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {visible.map((node) => {
                const rowId = `${node.organisation_id}:${node.id}`;
                const open = openId === rowId;
                const state = nodeState(node);
                return (
                  <DeviceRow
                    key={rowId}
                    node={node}
                    people={people}
                    open={open}
                    pending={pending}
                    state={state}
                    onToggle={() => setOpenId(open ? null : rowId)}
                    onRefresh={() => router.refresh()}
                    onConfirm={setConfirm}
                  />
                );
              })}
            </tbody>
        </Table>
      )}
      <ConfirmDialog
        open={confirm !== null}
        title={confirm?.kind === "revoke" ? "Revoke device access" : "Delete from inventory"}
        description={
          confirm
            ? confirm.kind === "revoke"
              ? `${nodeLabel(confirm.node)} will lose access to ${confirm.node.organisation_name} straight away. This can't be undone; the device would need to enrol again.`
              : `${nodeLabel(confirm.node)} is removed from the ${confirm.node.organisation_name} inventory. An audit tombstone is kept. This is separate from revoking access.`
            : null
        }
        confirmText={confirm ? nodeLabel(confirm.node) : undefined}
        confirmLabel={confirm?.kind === "revoke" ? "Revoke access" : "Delete device"}
        pending={pending}
        onCancel={() => setConfirm(null)}
        onConfirm={() => {
          if (!confirm) return;
          const { node, kind } = confirm;
          const formData = new FormData();
          formData.set("nodeId", node.id);
          formData.set("organisationId", node.organisation_id);
          startTransition(async () => {
            const result =
              kind === "revoke"
                ? await revokeDeviceAction(formData)
                : await tombstoneDeviceAction(formData);
            const label = nodeLabel(node);
            toastResult(result, {
              success: kind === "revoke" ? "Device access revoked" : "Device removed from inventory",
              successDescription:
                kind === "revoke"
                  ? `${label} can no longer use this network.`
                  : `${label} is gone from the list. The audit tombstone remains.`,
            });
            setConfirm(null);
            if (result.ok) router.refresh();
          });
        }}
      />
    </div>
  );
}

function DeviceRow({
  node,
  people,
  open,
  pending: confirming,
  state,
  onToggle,
  onRefresh,
  onConfirm,
}: {
  node: NetworkNode;
  people: AclPerson[];
  open: boolean;
  pending: boolean;
  state: { label: string; tone: BadgeTone };
  onToggle: () => void;
  onRefresh: () => void;
  onConfirm: (confirm: { kind: "revoke" | "delete"; node: NetworkNode }) => void;
}) {
  const [nameError, setNameError] = useState<string | null>(null);
  const [renaming, startRename] = useTransition();
  const [savingRoutes, startRoutes] = useTransition();
  const pending = renaming || savingRoutes || confirming;
  const canEdit = can(node.effective_role, "manage_peers") && !node.revoked && !node.deleted;
  const canApproveRoutes =
    can(node.effective_role, "manage_networks") && !node.revoked && !node.deleted;
  const detailsId = `device-${node.id}`;

  return (
    <>
      <tr className={open ? "device-row open" : "device-row"}>
        <td>
          <div className="device-primary">
            <Link
              href={`/devices/${node.id}?organisation=${encodeURIComponent(node.organisation_id)}`}
            >
              {nodeLabel(node)}
            </Link>
          </div>
          <div className="device-sub">
            {node.dns_name || node.name}
            {node.display_name ? ` · ${node.name}` : ""}
          </div>
        </td>
        <td>
          <Badge tone="brand">{node.network_account_name}</Badge>
          <div className="device-sub">{ownerLabel(node, people)}</div>
        </td>
        <td className="device-address">
          {node.allowed_ips.length > 0 ? (
            node.allowed_ips.slice(0, 2).map((ip) => (
              <div key={ip}>
                <MonoValue value={ip} />
              </div>
            ))
          ) : (
            <span className="mono">{node.dns_name || "—"}</span>
          )}
        </td>
        <td>
          <StatusPill tone={state.tone}>{state.label}</StatusPill>
        </td>
        <td>
          <Button
            size="sm"
            variant="secondary"
            aria-expanded={open}
            aria-controls={detailsId}
            aria-label={`${open ? "Hide" : "Show"} details for ${nodeLabel(node)}`}
            onClick={onToggle}
          >
            {open ? "Hide" : "Details"}
          </Button>
        </td>
      </tr>
      {open ? (
        <tr className="device-details-row">
          <td colSpan={5}>
            <div className="device-details" id={detailsId}>
              <dl className="details">
                <div>
                  <dt>Organisation</dt>
                  <dd>{node.organisation_name}</dd>
                </div>
                <div>
                  <dt>Last seen</dt>
                  <dd>{formatSeen(node.last_seen_at)}</dd>
                </div>
                <div>
                  <dt>Credential</dt>
                  <dd>
                    <time
                      dateTime={new Date(
                        node.credential_expires_at * 1000,
                      ).toISOString()}
                    >
                      {new Date(node.credential_expires_at * 1000).toLocaleDateString(
                        "en-AU",
                        { dateStyle: "medium" },
                      )}
                    </time>
                  </dd>
                </div>
                <div>
                  <dt>Machine</dt>
                  <dd>
                    {node.os || "Unknown OS"}
                    {node.os_version ? ` ${node.os_version}` : ""}
                    {node.hostname ? ` · ${node.hostname}` : ""}
                    {node.agent_version ? (
                      <div className="muted mono">{node.agent_version}</div>
                    ) : null}
                  </dd>
                </div>
                <div>
                  <dt>Addresses</dt>
                  <dd className="value-list">
                    {node.allowed_ips.length > 0
                      ? node.allowed_ips.map((ip) => (
                          <MonoValue key={ip} value={ip} copy copyLabel={`Copy address ${ip}`} />
                        ))
                      : "None"}
                  </dd>
                </div>
                <div>
                  <dt>Tags</dt>
                  <dd>
                    {node.tags.length > 0 ? (
                      <span className="tag-list">
                        {node.tags.map((tag) => (
                          <Badge key={tag}>{tag}</Badge>
                        ))}
                      </span>
                    ) : (
                      "None"
                    )}
                  </dd>
                </div>
              </dl>

              {canEdit ? (
                <form
                  className="device-name-editor"
                  onSubmit={(event) => {
                    event.preventDefault();
                    const formData = new FormData(event.currentTarget);
                    startRename(async () => {
                      const result = await updateDeviceFriendlyNameAction(formData);
                      setNameError(
                        toastResult(result, {
                          success: "Device renamed",
                          successDescription: result.ok
                            ? result.data.friendlyName
                              ? `${node.name} is now shown as ${result.data.friendlyName}.`
                              : `${node.name} now uses its original name.`
                            : undefined,
                          errorToast: false,
                        }).friendlyName ?? null,
                      );
                      if (result.ok) onRefresh();
                    });
                  }}
                >
                  <input type="hidden" name="nodeId" value={node.id} />
                  <input
                    type="hidden"
                    name="organisationId"
                    value={node.organisation_id}
                  />
                  <FormField
                    label="Friendly name"
                    hint="Shown in lists. Leave blank to use the device's own name."
                    error={nameError}
                  >
                    <input
                      name="friendlyName"
                      type="text"
                      maxLength={64}
                      defaultValue={node.display_name ?? ""}
                      placeholder={node.name}
                      disabled={pending}
                    />
                  </FormField>
                  <Button
                    type="submit"
                    variant="secondary"
                    loading={renaming}
                    disabled={pending}
                    loadingLabel="Saving…"
                  >
                    Save name
                  </Button>
                </form>
              ) : null}

              {(node.shares ?? []).some((share) => share.enabled) ? (
                <div>
                  <p className="eyebrow">Shared folders</p>
                  <ul className="muted">
                    {(node.shares ?? [])
                      .filter((share) => share.enabled)
                      .map((share) => (
                        <li key={`${node.id}-${share.label}`}>
                          <span className="mono">
                            http://{node.dns_name}:{share.port}/{share.label}/
                          </span>
                          {share.read_only ? " · read-only" : " · accepts file send"}
                          {share.path ? ` · ${share.path}` : ""}
                        </li>
                      ))}
                  </ul>
                  <p className="muted">
                    Reachable over the overlay. Browse the URL or, on a Mac,
                    Finder → Go → Connect to Server. Policy must allow the
                    device; the share port is opened for peers that can already
                    see it.
                  </p>
                </div>
              ) : (
                <p className="muted">
                  No shared folders. On the device run{" "}
                  <span className="mono">
                    blaktaild share enable --path /absolute/dir --writable
                  </span>
                  .
                </p>
              )}

              {node.advertised_routes.length > 0 ? (
                <form
                  className="route-approval"
                  onSubmit={(event) => {
                    event.preventDefault();
                    const formData = new FormData(event.currentTarget);
                    startRoutes(async () => {
                      const result = await approveNodeRoutesAction(formData);
                      toastResult(result, {
                        success: "Route approvals saved",
                        successDescription: `${nodeLabel(node)} now uses the routes you approved.`,
                      });
                      if (result.ok) onRefresh();
                    });
                  }}
                >
                  <input type="hidden" name="nodeId" value={node.id} />
                  <input
                    type="hidden"
                    name="organisationId"
                    value={node.organisation_id}
                  />
                  <fieldset className="ui-fieldset">
                  <legend>Advertised routes</legend>
                  <p className="ui-field-hint">
                    Approved routes are offered to every device policy lets reach this one.
                  </p>
                  <div className="ui-choices">
                  {node.advertised_routes.map((route) => (
                    <label key={route} className="route-option mono">
                      <input
                        type="checkbox"
                        name="approvedRoutes"
                        value={route}
                        defaultChecked={node.approved_routes.includes(route)}
                        disabled={
                          !canApproveRoutes ||
                          pending ||
                          (node.expired && !node.approved_routes.includes(route))
                        }
                      />
                      {route === "0.0.0.0/0" ? "Exit node (0.0.0.0/0)" : route === "::/0" ? "IPv6 exit node (::/0)" : route}
                    </label>
                  ))}
                  </div>
                  {canApproveRoutes && (!node.expired || node.approved_routes.length > 0) ? (
                    <div className="ui-form-actions">
                      <Button
                        type="submit"
                        variant="secondary"
                        loading={savingRoutes}
                        disabled={pending}
                        loadingLabel="Saving…"
                      >
                        Save routes
                      </Button>
                    </div>
                  ) : null}
                  </fieldset>
                </form>
              ) : (
                <p className="muted">This device is not advertising routes.</p>
              )}

              {canEdit ? (
                <div className="danger-zone">
                  <p className="eyebrow">Consequences</p>
                  <p className="muted">
                    Revoke cuts this device off the network immediately. Delete
                    only removes it from the inventory and keeps an audit
                    tombstone. Neither action can be undone from this page.
                  </p>
                  <div className="actions">
                    <Button
                      variant="danger"
                      disabled={pending}
                      onClick={() => onConfirm({ kind: "revoke", node })}
                    >
                      Revoke access
                    </Button>
                    <Button
                      variant="quiet-danger"
                      disabled={pending}
                      onClick={() => onConfirm({ kind: "delete", node })}
                    >
                      Delete from inventory
                    </Button>
                    <Link
                      className="button ghost"
                      href={`/devices/${node.id}?organisation=${encodeURIComponent(node.organisation_id)}`}
                    >
                      Suspend or see more
                    </Link>
                  </div>
                </div>
              ) : null}
            </div>
          </td>
        </tr>
      ) : null}
    </>
  );
}
