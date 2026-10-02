"use client";

import { useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  previewNetworkResourceAction,
  saveNetworkResourceAction,
} from "@/app/networks/actions";
import type { NetworkResource } from "@/lib/coord-networks";
import { can, permissionReason, roleLabel, type OrgRole } from "@/lib/roles";

export type RoutingPeerChoice = {
  id: string;
  label: string;
  advertisedRoutes: string[];
  online: boolean;
};

const STEPS = ["Destination", "Routing peers", "Access", "Review"] as const;

export function NetworkResourceForm({
  organisationId,
  organisationName,
  role,
  peers,
  groups,
  existing,
}: {
  organisationId: string;
  organisationName: string;
  role: OrgRole;
  peers: RoutingPeerChoice[];
  groups: string[];
  existing?: NetworkResource;
}) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [step, setStep] = useState(0);
  const [kind, setKind] = useState<"cidr" | "dns">(existing?.kind ?? "cidr");
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<NetworkResource | null>(null);
  const denied = permissionReason(role, "manage_networks");
  const isOwner = role === "owner";
  const metricFor = (id: string) =>
    existing?.routing_peers.find((peer) => peer.node_id === id)?.metric ?? 100;

  function formData(): FormData {
    const data = new FormData(formRef.current ?? undefined);
    data.set("organisationId", organisationId);
    if (existing) {
      data.set("resourceId", existing.id);
      data.set("etag", existing.etag);
    }
    return data;
  }

  function check() {
    setError(null);
    setPreview(null);
    startTransition(async () => {
      const result = await previewNetworkResourceAction(formData());
      if (result.ok) setPreview(result.data);
      else setError(result.error);
    });
  }

  if (!can(role, "manage_networks")) {
    return <p className="muted">{denied}</p>;
  }

  return (
    <form
      ref={formRef}
      className="panel stack"
      onSubmit={(event) => {
        event.preventDefault();
        setError(null);
        startTransition(async () => {
          const result = await saveNetworkResourceAction(formData());
          if (!result.ok) {
            setError(result.error);
            return;
          }
          router.push(`/networks/${result.data.id}`);
          router.refresh();
        });
      }}
    >
      <div className="row">
        <span className="badge network">{organisationName}</span>
        <span className="muted">Acting as {roleLabel(role)}</span>
      </div>
      <ol className="ceremony" aria-label="Steps">
        {STEPS.map((label, index) => (
          <li key={label} aria-current={index === step ? "step" : undefined}>
            {index === step ? <strong>{label}</strong> : label}
          </li>
        ))}
      </ol>

      <fieldset hidden={step !== 0} className="stack">
        <legend>Destination</legend>
        <label>
          Name
          <input name="name" required maxLength={64} defaultValue={existing?.name} />
        </label>
        <label>
          Description
          <input name="description" maxLength={256} defaultValue={existing?.description} />
        </label>
        <div className="row" role="radiogroup" aria-label="Destination type">
          <label className="route-option">
            <input
              type="radio"
              name="kind"
              value="cidr"
              checked={kind === "cidr"}
              onChange={() => setKind("cidr")}
            />
            IPv4 or IPv6 subnet
          </label>
          <label className="route-option">
            <input
              type="radio"
              name="kind"
              value="dns"
              checked={kind === "dns"}
              onChange={() => setKind("dns")}
            />
            Exact DNS name
          </label>
        </div>
        <label>
          {kind === "cidr" ? "Subnet (CIDR)" : "DNS name"}
          <input
            className="mono"
            name="target"
            required
            defaultValue={existing?.cidr ?? existing?.dns_target ?? ""}
            placeholder={kind === "cidr" ? "10.20.1.0/24 or fd12:3456::/48" : "files.example.org.au"}
          />
        </label>
        {kind === "dns" ? (
          <p className="muted">
            DNS names are recorded but not resolved or routed yet; that needs the
            domain connector work. The resource will show as not resolved.
          </p>
        ) : null}
        <label>
          Destination ports (optional)
          <input
            className="mono"
            name="ports"
            defaultValue={existing?.ports.join(", ")}
            placeholder="443, 8000-8080"
          />
        </label>
        <fieldset>
          <legend>Protocols (optional)</legend>
          {(["tcp", "udp", "icmp"] as const).map((protocol) => (
            <label key={protocol} className="route-option">
              <input
                type="checkbox"
                name="protocols"
                value={protocol}
                defaultChecked={existing?.protocols.includes(protocol)}
              />
              {protocol.toUpperCase()}
            </label>
          ))}
        </fieldset>
        <p className="muted">
          Ports and protocols are recorded for review but are not yet enforced
          by the routing peer, which forwards the whole subnet. Restrict ports
          with access policy on the destination devices.
        </p>
      </fieldset>

      <fieldset hidden={step !== 1} className="stack">
        <legend>Routing peers</legend>
        <p className="muted">
          A routing peer carries the subnet only if it advertises a covering
          route. Clients use the online peer with the lowest metric; the next
          one takes over when it goes offline.
        </p>
        {peers.length === 0 ? (
          <p className="muted">
            No devices in {organisationName} can be routing peers yet. Start a
            Linux agent with <span className="mono">--advertise-routes</span>.
          </p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Use</th>
                  <th>Device</th>
                  <th>Advertises</th>
                  <th>Metric</th>
                </tr>
              </thead>
              <tbody>
                {peers.map((peer) => (
                  <tr key={peer.id}>
                    <td>
                      <input
                        type="checkbox"
                        name="routingPeer"
                        value={peer.id}
                        aria-label={`Use ${peer.label} as a routing peer`}
                        defaultChecked={existing?.routing_peers.some(
                          (item) => item.node_id === peer.id,
                        )}
                      />
                    </td>
                    <td>
                      {peer.label}{" "}
                      <span className={peer.online ? "badge online" : "badge offline"}>
                        {peer.online ? "Online" : "Offline"}
                      </span>
                    </td>
                    <td className="mono">
                      {peer.advertisedRoutes.join(", ") || "Nothing"}
                    </td>
                    <td>
                      <input
                        type="number"
                        name={`metric:${peer.id}`}
                        min={1}
                        max={9999}
                        defaultValue={metricFor(peer.id)}
                        aria-label={`Metric for ${peer.label}`}
                      />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        <dl className="details">
          <div>
            <dt>Masquerade (NAT)</dt>
            <dd>
              Always on. The Linux agent rewrites overlay sources to the routing
              peer&apos;s LAN address; forwarding without NAT is not supported yet.
            </dd>
          </div>
        </dl>
      </fieldset>

      <fieldset hidden={step !== 2} className="stack">
        <legend>Who receives this route</legend>
        <p className="muted">
          Devices matching any selection below receive the exact prefix, and
          only when access policy also lets them reach the routing peer.
        </p>
        <fieldset>
          <legend>Device owner roles</legend>
          {(["owner", "admin", "member"] as const).map((item) => (
            <label key={item} className="route-option">
              <input
                type="checkbox"
                name="accessRoles"
                value={item}
                defaultChecked={existing?.access.roles.includes(item)}
              />
              {roleLabel(item)}
            </label>
          ))}
        </fieldset>
        <fieldset>
          <legend>Device tags</legend>
          {(["office", "ranger", "store"] as const).map((tag) => (
            <label key={tag} className="route-option">
              <input
                type="checkbox"
                name="accessTags"
                value={tag}
                defaultChecked={existing?.access.tags.includes(tag)}
              />
              {tag}
            </label>
          ))}
        </fieldset>
        <fieldset>
          <legend>Policy groups</legend>
          {groups.length === 0 ? (
            <p className="muted">No groups yet. Define people groups in Access policy.</p>
          ) : (
            groups.map((group) => (
              <label key={group} className="route-option">
                <input
                  type="checkbox"
                  name="accessGroups"
                  value={group}
                  defaultChecked={existing?.access.groups.includes(group)}
                />
                {group}
              </label>
            ))
          )}
        </fieldset>
      </fieldset>

      <fieldset hidden={step !== 3} className="stack">
        <legend>Review</legend>
        <label className="route-option">
          <input
            type="checkbox"
            name="allowNestedOverlap"
            defaultChecked={existing?.allow_nested_overlap}
          />
          Allow this subnet to sit inside or around another resource (the more
          specific prefix wins on clients). Exact duplicates are always refused.
        </label>
        <label className="route-option">
          <input type="checkbox" name="confirmPublicRoute" disabled={!isOwner} />
          I confirm this default or public route as the organisation owner.
        </label>
        {!isOwner ? (
          <p className="muted">
            Only an organisation owner can confirm 0.0.0.0/0, ::/0 or public
            prefixes. Private subnets do not need this.
          </p>
        ) : null}
        <input type="hidden" name="enabled" value={existing ? String(existing.enabled) : "true"} />
        <div className="actions">
          <button type="button" className="secondary" disabled={pending} onClick={check}>
            {pending ? "Checking…" : "Check overlaps and distribution"}
          </button>
        </div>
        {preview ? (
          <div className="stack" aria-live="polite">
            <p>
              No conflicts. State once saved:{" "}
              <strong>{preview.status.state.replaceAll("_", " ")}</strong>.
            </p>
            <p className="muted">
              {preview.status.clients.filter((client) => client.receives).length} of{" "}
              {preview.status.clients.length} other devices would receive this route.
            </p>
          </div>
        ) : null}
      </fieldset>

      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      <div className="actions">
        {step > 0 ? (
          <button type="button" className="secondary" onClick={() => setStep(step - 1)}>
            Back
          </button>
        ) : null}
        {step < STEPS.length - 1 ? (
          <button
            type="button"
            onClick={() => {
              if (formRef.current?.reportValidity() ?? true) setStep(step + 1);
            }}
          >
            Next
          </button>
        ) : (
          <button type="submit" disabled={pending}>
            {pending ? "Saving…" : existing ? "Save changes" : "Create resource"}
          </button>
        )}
      </div>
    </form>
  );
}
