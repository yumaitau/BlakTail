"use client";

import { useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  previewNetworkResourceAction,
  saveNetworkResourceAction,
} from "@/app/networks/actions";
import type { NetworkResource } from "@/lib/coord-networks";
import { can, permissionReason, roleLabel, type OrgRole } from "@/lib/roles";
import { Alert } from "./ui/alert";
import { StatusPill } from "./ui/badge";
import { Button } from "./ui/button";
import { FormField } from "./ui/form-field";
import { MonoValue } from "./ui/mono-value";
import { PermissionNotice } from "./ui/permission-notice";
import { Table, Td } from "./ui/table";
import { toastResult } from "./ui/toast";

export type RoutingPeerChoice = {
  id: string;
  label: string;
  advertisedRoutes: string[];
  online: boolean;
};

const STEPS = ["Destination", "Routing peers", "Access", "Review"] as const;
/** Which step shows each field, so a server field error opens the right step. */
const FIELD_STEP: Record<string, number> = { name: 0, target: 0, ports: 0 };

export function NetworkResourceForm({
  organisationId,
  role,
  peers,
  groups,
  existing,
}: {
  organisationId: string;
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
  const [checking, setChecking] = useState(false);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<NetworkResource | null>(null);
  const denied = permissionReason(role, "manage_networks");
  const isOwner = role === "owner";
  const metricFor = (id: string) =>
    existing?.routing_peers.find((peer) => peer.node_id === id)?.metric ?? 100;
  const idPrefix = existing ? `resource-${existing.id}` : "resource-new";

  function formData(): FormData {
    const data = new FormData(formRef.current ?? undefined);
    data.set("organisationId", organisationId);
    if (existing) {
      data.set("resourceId", existing.id);
      data.set("etag", existing.etag);
    }
    return data;
  }

  /** Shows field errors and jumps to the first step that has one. */
  function showErrors(errors: Record<string, string>) {
    setFieldErrors(errors);
    const steps = Object.keys(errors)
      .map((field) => FIELD_STEP[field])
      .filter((value): value is number => value !== undefined);
    if (steps.length > 0) setStep(Math.min(...steps));
  }

  function checkDestination(): boolean {
    const data = formData();
    const errors: Record<string, string> = {};
    if (!String(data.get("name") ?? "").trim()) errors.name = "Give the resource a name.";
    if (!String(data.get("target") ?? "").trim()) {
      errors.target =
        kind === "cidr" ? "Enter a subnet, such as 10.20.1.0/24." : "Enter a DNS name.";
    }
    setFieldErrors(errors);
    if (errors.name || errors.target) {
      formRef.current
        ?.querySelector<HTMLInputElement>(`[name="${errors.name ? "name" : "target"}"]`)
        ?.focus();
      return false;
    }
    return true;
  }

  function check() {
    setPreview(null);
    setChecking(true);
    startTransition(async () => {
      const result = await previewNetworkResourceAction(formData());
      setChecking(false);
      if (result.ok) {
        setPreview(result.data);
        return;
      }
      showErrors(toastResult(result, { errorToast: true }));
    });
  }

  if (!can(role, "manage_networks")) {
    return <PermissionNotice reason={denied ?? ""} />;
  }

  return (
    <form
      ref={formRef}
      className="ui-form wide"
      noValidate
      onChange={() => setPreview(null)}
      onSubmit={(event) => {
        event.preventDefault();
        if (step < STEPS.length - 1) {
          if (step === 0 && !checkDestination()) return;
          setStep(step + 1);
          return;
        }
        startTransition(async () => {
          const result = await saveNetworkResourceAction(formData());
          const errors = toastResult(result, {
            success: existing ? "Resource saved" : "Resource created",
            successDescription: "Clients pick up the change on their next sync, within about 25 seconds.",
            errorToast: true,
          });
          if (!result.ok) {
            showErrors(errors);
            return;
          }
          router.push(`/networks/${result.data.id}`);
          router.refresh();
        });
      }}
    >
      <ol className="ceremony wizard-steps" aria-label="Steps">
        {STEPS.map((label, index) => (
          <li key={label} aria-current={index === step ? "step" : undefined}>
            {label}
          </li>
        ))}
      </ol>

      <div hidden={step !== 0} className="ui-form">
        <div className="ui-form-grid">
          <FormField label="Name" hint="Shown in lists and the Control Center." required error={fieldErrors.name}>
            <input
              id={`${idPrefix}-name`}
              name="name"
              maxLength={64}
              defaultValue={existing?.name}
              placeholder="Darwin office LAN"
            />
          </FormField>
          <FormField label="Description" hint="Optional. What lives there.">
            <input
              id={`${idPrefix}-description`}
              name="description"
              maxLength={256}
              defaultValue={existing?.description}
            />
          </FormField>
        </div>
        <fieldset className="ui-fieldset">
          <legend>Destination type</legend>
          <div className="ui-choices">
            <label>
              <input
                type="radio"
                name="kind"
                value="cidr"
                checked={kind === "cidr"}
                onChange={() => setKind("cidr")}
              />
              IPv4 or IPv6 subnet
            </label>
            <label>
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
          <FormField
            label={kind === "cidr" ? "Subnet (CIDR)" : "DNS name"}
            hint={
              kind === "dns"
                ? "DNS names are recorded but not routed until an app connector resolves them, so the resource shows as not resolved."
                : "An IPv4 or IPv6 prefix, such as 10.20.1.0/24 or fd12:3456::/48."
            }
            required
            error={fieldErrors.target}
            className="field-md"
          >
            <input
              id={`${idPrefix}-target`}
              className="mono"
              name="target"
              defaultValue={existing?.cidr ?? existing?.dns_target ?? ""}
              placeholder={kind === "cidr" ? "10.20.1.0/24" : "files.example.org.au"}
              spellCheck={false}
              autoComplete="off"
            />
          </FormField>
        </fieldset>
        <fieldset className="ui-fieldset">
          <legend>Ports and protocols</legend>
          <p className="ui-field-hint">
            Optional. Routing peers that report forward filtering pass only these ports and
            protocols, and only for authorised devices. Older routing peers forward the whole
            subnet; the resource page says which.
          </p>
          <FormField
            label="Destination ports"
            hint="Comma-separated ports or ranges. Leave blank for any port."
            error={fieldErrors.ports}
            className="field-md"
          >
            <input
              id={`${idPrefix}-ports`}
              className="mono"
              name="ports"
              defaultValue={existing?.ports.join(", ")}
              placeholder="443, 8000-8080"
            />
          </FormField>
          <div className="ui-choices" role="group" aria-label="Protocols">
            {(["tcp", "udp", "icmp"] as const).map((protocol) => (
              <label key={protocol}>
                <input
                  type="checkbox"
                  name="protocols"
                  value={protocol}
                  defaultChecked={existing?.protocols.includes(protocol)}
                />
                {protocol.toUpperCase()}
              </label>
            ))}
          </div>
        </fieldset>
      </div>

      <fieldset hidden={step !== 1} className="ui-fieldset">
        <legend>Routing peers</legend>
        <p className="ui-field-hint">
          A routing peer carries the subnet only if it advertises a covering route. Clients use
          the online peer with the lowest metric; the next one takes over when it goes offline.
          Masquerade (NAT) is always on: the Linux agent rewrites overlay sources to the routing
          peer&apos;s LAN address.
        </p>
        {peers.length === 0 ? (
          <Alert tone="info" title="No routing peers available">
            No active device can carry a route yet. Start a Linux agent with{" "}
            <span className="mono">--advertise-routes</span>, then come back.
          </Alert>
        ) : (
          <Table label="Routing peer choices" mobile="stack">
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
                  <Td label="Use">
                    <input
                      type="checkbox"
                      name="routingPeer"
                      value={peer.id}
                      aria-label={`Use ${peer.label} as a routing peer`}
                      defaultChecked={existing?.routing_peers.some(
                        (item) => item.node_id === peer.id,
                      )}
                    />
                  </Td>
                  <Td label="Device">
                    <div>
                      {peer.label}{" "}
                      <StatusPill tone={peer.online ? "success" : "muted"}>
                        {peer.online ? "Online" : "Offline"}
                      </StatusPill>
                    </div>
                  </Td>
                  <Td label="Advertises">
                    {peer.advertisedRoutes.length > 0 ? (
                      <span className="route-list">
                        {peer.advertisedRoutes.map((route) => (
                          <MonoValue key={route} value={route} />
                        ))}
                      </span>
                    ) : (
                      <span className="muted">Nothing</span>
                    )}
                  </Td>
                  <Td label="Metric">
                    <input
                      type="number"
                      name={`metric:${peer.id}`}
                      min={1}
                      max={9999}
                      defaultValue={metricFor(peer.id)}
                      aria-label={`Metric for ${peer.label}`}
                      className="metric-input"
                    />
                  </Td>
                </tr>
              ))}
            </tbody>
          </Table>
        )}
      </fieldset>

      <div hidden={step !== 2} className="ui-form">
        <p className="ui-field-hint">
          Devices matching any selection below receive the exact prefix, and only when access
          policy also lets them reach the routing peer.
        </p>
        <fieldset className="ui-fieldset">
          <legend>Device owner roles</legend>
          <div className="ui-choices">
            {(["owner", "admin", "member"] as const).map((item) => (
              <label key={item}>
                <input
                  type="checkbox"
                  name="accessRoles"
                  value={item}
                  defaultChecked={existing?.access.roles.includes(item)}
                />
                {roleLabel(item)}
              </label>
            ))}
          </div>
        </fieldset>
        <fieldset className="ui-fieldset">
          <legend>Device tags</legend>
          <div className="ui-choices">
            {(["office", "ranger", "store"] as const).map((tag) => (
              <label key={tag}>
                <input
                  type="checkbox"
                  name="accessTags"
                  value={tag}
                  defaultChecked={existing?.access.tags.includes(tag)}
                />
                {tag}
              </label>
            ))}
          </div>
        </fieldset>
        <fieldset className="ui-fieldset">
          <legend>Policy groups</legend>
          {groups.length === 0 ? (
            <p className="ui-field-hint">No groups yet. Define people groups in Access policy.</p>
          ) : (
            <div className="ui-choices">
              {groups.map((group) => (
                <label key={group}>
                  <input
                    type="checkbox"
                    name="accessGroups"
                    value={group}
                    defaultChecked={existing?.access.groups.includes(group)}
                  />
                  {group}
                </label>
              ))}
            </div>
          )}
        </fieldset>
      </div>

      <div hidden={step !== 3} className="ui-form">
        <fieldset className="ui-fieldset">
          <legend>Overlaps and public routes</legend>
          <div className="ui-choices vertical">
            <label>
              <input
                type="checkbox"
                name="allowNestedOverlap"
                defaultChecked={existing?.allow_nested_overlap}
              />
              Allow this subnet to sit inside or around another resource (the more specific
              prefix wins). Exact duplicates are always refused.
            </label>
            <label>
              <input type="checkbox" name="confirmPublicRoute" disabled={!isOwner} />
              I confirm this default or public route as the organisation owner.
            </label>
          </div>
          {!isOwner ? (
            <p className="ui-field-hint">
              Only an organisation owner can confirm 0.0.0.0/0, ::/0 or public prefixes. Private
              subnets don&apos;t need this.
            </p>
          ) : null}
        </fieldset>
        <input type="hidden" name="enabled" value={existing ? String(existing.enabled) : "true"} />
        <div>
          <Button
            variant="secondary"
            loading={checking}
            loadingLabel="Checking…"
            disabled={pending}
            onClick={check}
          >
            Check overlaps and distribution
          </Button>
        </div>
        {preview ? (
          <Alert tone="success" title="No conflicts">
            Once saved the resource will be{" "}
            <strong>{preview.status.state.replaceAll("_", " ")}</strong>.{" "}
            {preview.status.clients.filter((client) => client.receives).length} of{" "}
            {preview.status.clients.length} other devices would receive this route.
          </Alert>
        ) : null}
      </div>

      <div className="ui-form-actions">
        {step < STEPS.length - 1 ? (
          <Button type="submit">Next: {STEPS[step + 1]}</Button>
        ) : (
          <Button
            type="submit"
            loading={pending && !checking}
            loadingLabel="Saving…"
            disabled={checking}
          >
            {existing ? "Save changes" : "Create resource"}
          </Button>
        )}
        {step > 0 ? (
          <Button variant="secondary" disabled={pending} onClick={() => setStep(step - 1)}>
            Back
          </Button>
        ) : null}
      </div>
    </form>
  );
}
