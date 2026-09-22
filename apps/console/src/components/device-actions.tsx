"use client";

import { useMemo, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  approveNodeRoutesAction,
  revokeDeviceAction,
  tombstoneDeviceAction,
  updateDeviceFriendlyNameAction,
} from "@/app/actions";
import type { AclPerson } from "@/lib/acl";
import type { NetworkNode } from "@/lib/coord";
import { canMutateTailnet } from "@/lib/roles";
import { EmptyState } from "./empty-state";

type StatusFilter = "all" | "online" | "offline" | "attention";

function nodeLabel(node: NetworkNode): string {
  return node.display_name || node.name;
}

function nodeState(node: NetworkNode): {
  label: string;
  className: string;
} {
  if (node.deleted) return { label: "Deleted", className: "revoked" };
  if (node.revoked) return { label: "Revoked", className: "revoked" };
  if (node.expired) return { label: "Expired", className: "warn" };
  if (node.expires_soon) return { label: "Expires soon", className: "pending" };
  if (node.online) return { label: "Online", className: "online" };
  return { label: "Offline", className: "offline" };
}

function needsAttention(node: NetworkNode): boolean {
  return (
    !node.deleted &&
    (node.revoked ||
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
  return node.user_role;
}

export function DeviceActions({
  nodes,
  people,
}: {
  nodes: NetworkNode[];
  people: AclPerson[];
}) {
  const router = useRouter();
  const [message, setMessage] = useState<{
    text: string;
    error: boolean;
  } | null>(null);
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

  if (nodes.length === 0) {
    return (
      <EmptyState
        title="No devices yet"
        body="Bring your first device onto this network with a join key or browser enrolment."
      />
    );
  }

  return (
    <div className="stack">
      <div className="table-toolbar">
        <label className="search-field">
          Search devices
          <input
            value={query}
            onChange={(event) => setQuery(event.target.value)}
            placeholder="Name, DNS, network, or person"
          />
        </label>
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
        <p className="muted">No devices match that search.</p>
      ) : (
        <div className="table-wrap">
          <table className="table device-table">
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
                    onMessage={setMessage}
                    onRefresh={() => router.refresh()}
                    onConfirm={setConfirm}
                    startTransition={startTransition}
                  />
                );
              })}
            </tbody>
          </table>
        </div>
      )}
      {message ? (
        <p
          className={message.error ? "error" : "muted"}
          role={message.error ? "alert" : "status"}
          aria-live="polite"
        >
          {message.text}
        </p>
      ) : null}
      {confirm ? (
        <div className="confirm-backdrop">
          <div
            className="confirm-dialog"
            role="dialog"
            aria-modal="true"
            aria-labelledby="device-confirm-title"
          >
            <h2 id="device-confirm-title">
              {confirm.kind === "revoke"
                ? "Revoke device"
                : "Delete from inventory"}
            </h2>
            <p>
              {confirm.kind === "revoke"
                ? `Revoke ${nodeLabel(confirm.node)} on ${confirm.node.organisation_name}? The device will lose network access.`
                : `Delete ${nodeLabel(confirm.node)} from ${confirm.node.organisation_name} inventory? This keeps a tombstone for audit and is separate from revoke.`}
            </p>
            <div className="actions">
              <button
                type="button"
                className="secondary"
                autoFocus
                onClick={() => setConfirm(null)}
              >
                Cancel
              </button>
              <button
                type="button"
                className="danger"
                disabled={pending}
                onClick={() => {
                  const node = confirm.node;
                  const kind = confirm.kind;
                  const formData = new FormData();
                  formData.set("nodeId", node.id);
                  formData.set("organisationId", node.organisation_id);
                  setMessage(null);
                  setConfirm(null);
                  startTransition(async () => {
                    const result =
                      kind === "revoke"
                        ? await revokeDeviceAction(formData)
                        : await tombstoneDeviceAction(formData);
                    const label = nodeLabel(node);
                    setMessage({
                      text: result.ok
                        ? kind === "revoke"
                          ? `${label} revoked. It can no longer use this network.`
                          : `${label} removed from inventory. The audit tombstone remains.`
                        : result.error,
                      error: !result.ok,
                    });
                    if (result.ok) router.refresh();
                  });
                }}
              >
                {confirm.kind === "revoke" ? "Revoke device" : "Delete device"}
              </button>
            </div>
          </div>
        </div>
      ) : null}
    </div>
  );
}

function DeviceRow({
  node,
  people,
  open,
  pending,
  state,
  onToggle,
  onMessage,
  onRefresh,
  onConfirm,
  startTransition,
}: {
  node: NetworkNode;
  people: AclPerson[];
  open: boolean;
  pending: boolean;
  state: { label: string; className: string };
  onToggle: () => void;
  onMessage: (message: { text: string; error: boolean } | null) => void;
  onRefresh: () => void;
  onConfirm: (confirm: { kind: "revoke" | "delete"; node: NetworkNode }) => void;
  startTransition: (action: () => void) => void;
}) {
  const canEdit = canMutateTailnet(node.effective_role) && !node.revoked && !node.deleted;
  const detailsId = `device-${node.id}`;

  return (
    <>
      <tr className={open ? "device-row open" : "device-row"}>
        <td>
          <div className="device-primary">{nodeLabel(node)}</div>
          <div className="device-sub">
            {node.dns_name || node.name}
            {node.display_name ? ` · ${node.name}` : ""}
          </div>
        </td>
        <td>
          <span className="badge network">{node.network_account_name}</span>
          <div className="device-sub">{ownerLabel(node, people)}</div>
        </td>
        <td className="device-address">
          {node.allowed_ips.length > 0 ? (
            node.allowed_ips.slice(0, 2).map((ip) => (
              <div key={ip} className="mono">
                {ip}
              </div>
            ))
          ) : (
            <span className="mono">{node.dns_name || "—"}</span>
          )}
        </td>
        <td>
          <span className={`badge ${state.className}`}>{state.label}</span>
        </td>
        <td>
          <button
            type="button"
            className="secondary"
            aria-expanded={open}
            aria-controls={detailsId}
            onClick={onToggle}
          >
            {open ? "Hide" : "Details"}
          </button>
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
                  <dd className="mono">
                    {node.allowed_ips.join(", ") || "—"}
                  </dd>
                </div>
                <div>
                  <dt>Tags</dt>
                  <dd>
                    {node.tags.length > 0
                      ? node.tags.map((tag) => (
                          <span key={tag} className="badge">
                            {tag}
                          </span>
                        ))
                      : "None"}
                  </dd>
                </div>
              </dl>

              {canEdit ? (
                <form
                  className="device-name-editor"
                  onSubmit={(event) => {
                    event.preventDefault();
                    const formData = new FormData(event.currentTarget);
                    onMessage(null);
                    startTransition(() => {
                      void updateDeviceFriendlyNameAction(formData).then(
                        (result) => {
                          onMessage({
                            text: result.ok
                              ? result.data.friendlyName
                                ? `${node.name} is now shown as ${result.data.friendlyName}.`
                                : `${node.name} now uses its original name.`
                              : result.error,
                            error: !result.ok,
                          });
                          if (result.ok) onRefresh();
                        },
                      );
                    });
                  }}
                >
                  <input type="hidden" name="nodeId" value={node.id} />
                  <input
                    type="hidden"
                    name="organisationId"
                    value={node.organisation_id}
                  />
                  <label>
                    Friendly name
                    <input
                      name="friendlyName"
                      type="text"
                      maxLength={64}
                      defaultValue={node.display_name ?? ""}
                      placeholder={node.name}
                      disabled={pending}
                    />
                  </label>
                  <button type="submit" className="secondary" disabled={pending}>
                    Save name
                  </button>
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
                    onMessage(null);
                    startTransition(() => {
                      void approveNodeRoutesAction(formData).then((result) => {
                        onMessage({
                          text: result.ok
                            ? `${nodeLabel(node)} route approvals saved.`
                            : result.error,
                          error: !result.ok,
                        });
                        if (result.ok) onRefresh();
                      });
                    });
                  }}
                >
                  <p className="eyebrow">Advertised routes</p>
                  <input type="hidden" name="nodeId" value={node.id} />
                  <input
                    type="hidden"
                    name="organisationId"
                    value={node.organisation_id}
                  />
                  {node.advertised_routes.map((route) => (
                    <label key={route} className="route-option mono">
                      <input
                        type="checkbox"
                        name="approvedRoutes"
                        value={route}
                        defaultChecked={node.approved_routes.includes(route)}
                        disabled={
                          !canEdit ||
                          pending ||
                          (node.expired && !node.approved_routes.includes(route))
                        }
                      />
                      {route === "0.0.0.0/0" ? "Exit node" : route}
                    </label>
                  ))}
                  {canEdit && (!node.expired || node.approved_routes.length > 0) ? (
                    <button type="submit" className="secondary" disabled={pending}>
                      Save routes
                    </button>
                  ) : null}
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
                    <button
                      type="button"
                      className="danger"
                      disabled={pending}
                      onClick={() => onConfirm({ kind: "revoke", node })}
                    >
                      Revoke access
                    </button>
                    <button
                      type="button"
                      className="quiet-danger"
                      disabled={pending}
                      onClick={() => onConfirm({ kind: "delete", node })}
                    >
                      Delete from inventory
                    </button>
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
