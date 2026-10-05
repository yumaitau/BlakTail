"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  createWgOnlyPeerAction,
  rotateWgOnlyPeerAction,
  revokeWgOnlyPeerAction,
} from "@/app/actions";
import { ACL_TAGS } from "@/lib/acl";
import { permissionReason, type OrgRole } from "@/lib/roles";
import type { NetworkWgOnlyPeer } from "@/lib/coord";
import { EmptyState } from "./empty-state";
import { Alert } from "./ui/alert";
import { Badge, StatusPill } from "./ui/badge";
import { Button } from "./ui/button";
import { ConfirmDialog } from "./ui/confirm-dialog";
import { FormField } from "./ui/form-field";
import { LocalTime } from "./ui/local-time";
import { MonoValue } from "./ui/mono-value";
import { PermissionNotice } from "./ui/permission-notice";
import { Section } from "./ui/section";
import { Table, Td } from "./ui/table";
import { toastResult } from "./ui/toast";

export function WgOnlyManager({
  peers,
  errors,
  role,
  organisationId,
}: {
  peers: NetworkWgOnlyPeer[];
  errors: string[];
  role: OrgRole;
  organisationId: string;
}) {
  const router = useRouter();
  const denied = permissionReason(role, "manage_peers");
  const canMutate = denied === null;
  const [adding, startAdd] = useTransition();
  const [acting, startAct] = useTransition();
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [showForm, setShowForm] = useState(false);
  const [rotating, setRotating] = useState<NetworkWgOnlyPeer | null>(null);
  const [rotateKey, setRotateKey] = useState("");
  const [rotateError, setRotateError] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<NetworkWgOnlyPeer | null>(null);

  return (
    <Section
      id="unmanaged"
      title="Unmanaged WireGuard peers"
      description={
        <>
          Public-key-only endpoints such as printers or appliances (peer kind{" "}
          <span className="mono nowrap">wireguard_only</span>). BlakTail never stores their private
          key, and policy on managed agents decides who receives them.
        </>
      }
      actions={
        canMutate && !showForm ? (
          <Button variant="secondary" onClick={() => setShowForm(true)}>
            Add peer
          </Button>
        ) : null
      }
    >
      {errors.map((item) => (
        <Alert tone="error" key={item} title="Some peers couldn't be listed">
          {item}
        </Alert>
      ))}
      {!canMutate && denied ? <PermissionNotice reason={denied} /> : null}
      {canMutate && showForm ? (
        <form
          className="ui-form wide"
          noValidate
          aria-label="Add an unmanaged WireGuard peer"
          onSubmit={(event) => {
            event.preventDefault();
            const form = event.currentTarget;
            const data = new FormData(form);
            data.set("organisationId", organisationId);
            const name = String(data.get("name") ?? "").trim();
            startAdd(async () => {
              const result = await createWgOnlyPeerAction(data);
              setFieldErrors(
                toastResult(result, {
                  success: "Unmanaged peer added",
                  successDescription: `${name} is offered to devices that policy allows.`,
                  errorToast: false,
                }),
              );
              if (!result.ok) return;
              form.reset();
              setShowForm(false);
              router.refresh();
            });
          }}
        >
          <div className="ui-form-grid">
            <FormField label="Name" hint="Shown in lists and peer maps." required error={fieldErrors.name}>
              <input name="name" maxLength={64} placeholder="depot-printer" autoComplete="off" />
            </FormField>
            <FormField
              label="Endpoint"
              hint="Host and UDP port."
              required
              error={fieldErrors.endpoint}
            >
              <input
                className="mono"
                name="endpoint"
                placeholder="203.0.113.10:51820"
                autoComplete="off"
                spellCheck={false}
              />
            </FormField>
          </div>
          <FormField
            label="Public key"
            hint="The peer's base64 WireGuard public key. Never paste a private key."
            required
            error={fieldErrors.wgPublicKey}
          >
            <input
              className="mono"
              name="wgPublicKey"
              placeholder="base64 public key"
              autoComplete="off"
              spellCheck={false}
            />
          </FormField>
          <FormField
            label="Allowed IPs"
            hint="Address ranges routed to this peer, separated by commas."
            required
            error={fieldErrors.allowedIps}
            className="field-md"
          >
            <input
              className="mono"
              name="allowedIps"
              placeholder="10.0.0.10/32"
              autoComplete="off"
              spellCheck={false}
            />
          </FormField>
          <fieldset className="ui-fieldset">
            <legend>Tags</legend>
            <div className="ui-choices">
              {ACL_TAGS.map((tag) => (
                <label key={tag}>
                  <input type="checkbox" name="tags" value={tag} /> {tag}
                </label>
              ))}
            </div>
          </fieldset>
          <div className="ui-form-actions">
            <Button type="submit" loading={adding} loadingLabel="Adding…" data-testid="wg-only-add">
              Add unmanaged peer
            </Button>
            <Button
              variant="secondary"
              disabled={adding}
              onClick={() => {
                setShowForm(false);
                setFieldErrors({});
              }}
            >
              Cancel
            </Button>
          </div>
        </form>
      ) : null}
      {peers.length ? (
        <Table label="Unmanaged WireGuard peers" mobile="stack">
          <thead>
            <tr>
              <th>Name</th>
              <th>Endpoint</th>
              <th>Allowed IPs</th>
              <th>Public key</th>
              <th>State</th>
              <th>
                <span className="visually-hidden">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            {peers.map((peer) => (
              <tr key={peer.id}>
                <Td label="Name">
                  <div>
                    <div className="device-primary">{peer.name}</div>
                    <div className="cell-sub">{peer.organisation_name}</div>
                    {peer.tags.length > 0 ? (
                      <div className="tag-list">
                        {peer.tags.map((tag) => (
                          <Badge key={tag}>{tag}</Badge>
                        ))}
                      </div>
                    ) : null}
                  </div>
                </Td>
                <Td label="Endpoint">
                  <MonoValue value={peer.endpoint} />
                </Td>
                <Td label="Allowed IPs">
                  <MonoValue value={peer.allowed_ips.join(", ")} wrap />
                </Td>
                <Td label="Public key">
                  <MonoValue
                    value={peer.wg_public_key}
                    copy
                    copyLabel={`Copy ${peer.name} public key`}
                  >
                    {peer.wg_public_key.slice(0, 12)}…
                  </MonoValue>
                </Td>
                <Td label="State">
                  <div>
                    {peer.revoked_at ? (
                      <StatusPill tone="danger">Revoked</StatusPill>
                    ) : (
                      <StatusPill tone="success">Active</StatusPill>
                    )}
                    {peer.previous_wg_public_key && peer.overlap_until ? (
                      <div className="cell-sub">
                        Old key accepted until <LocalTime value={peer.overlap_until} />
                      </div>
                    ) : null}
                  </div>
                </Td>
                <Td>
                  {canMutate && !peer.revoked_at ? (
                    <div className="cell-actions">
                      <Button
                        size="sm"
                        variant="secondary"
                        disabled={acting}
                        data-testid="wg-only-rotate"
                        onClick={() => {
                          setRotateKey("");
                          setRotateError(null);
                          setRotating(peer);
                        }}
                      >
                        Rotate key
                      </Button>
                      <Button
                        size="sm"
                        variant="quiet-danger"
                        disabled={acting}
                        onClick={() => setRevoking(peer)}
                      >
                        Revoke
                      </Button>
                    </div>
                  ) : null}
                </Td>
              </tr>
            ))}
          </tbody>
        </Table>
      ) : errors.length === 0 ? (
        <EmptyState
          compact
          headingLevel={3}
          title="No unmanaged peers yet"
          body="Add a WireGuard-only endpoint, such as a printer or a site router, by its public key. It appears here with its endpoint and state."
        />
      ) : null}

      <ConfirmDialog
        open={rotating !== null}
        title="Rotate public key"
        tone="primary"
        description={
          rotating
            ? `Devices switch ${rotating.name} to the new key at their next update. The old key keeps working for five minutes so the change doesn't drop traffic.`
            : null
        }
        confirmLabel="Rotate key"
        pending={acting}
        onCancel={() => setRotating(null)}
        onConfirm={() => {
          if (!rotating) return;
          const data = new FormData();
          data.set("peerId", rotating.id);
          data.set("organisationId", rotating.organisation_id);
          data.set("wgPublicKey", rotateKey.trim());
          data.set("overlapSeconds", "300");
          const name = rotating.name;
          startAct(async () => {
            const result = await rotateWgOnlyPeerAction(data);
            const errors = toastResult(result, {
              success: "Public key rotated",
              successDescription: `${name} now uses the new key.`,
              errorToast: false,
            });
            setRotateError(errors.wgPublicKey ?? null);
            if (!result.ok && !errors.wgPublicKey) {
              toastResult(result);
            }
            if (!result.ok) return;
            setRotating(null);
            router.refresh();
          });
        }}
      >
        <FormField
          label="New public key"
          hint="Base64 WireGuard public key."
          required
          error={rotateError}
        >
          <input
            className="mono"
            value={rotateKey}
            onChange={(event) => setRotateKey(event.target.value)}
            autoComplete="off"
            spellCheck={false}
          />
        </FormField>
      </ConfirmDialog>

      <ConfirmDialog
        open={revoking !== null}
        title="Revoke unmanaged peer"
        description={
          revoking
            ? `${revoking.name} is removed from every device's peer list at the next update. This can't be undone; add it again to restore it.`
            : null
        }
        confirmText={revoking?.name}
        confirmLabel="Revoke peer"
        pending={acting}
        onCancel={() => setRevoking(null)}
        onConfirm={() => {
          if (!revoking) return;
          const data = new FormData();
          data.set("peerId", revoking.id);
          data.set("organisationId", revoking.organisation_id);
          const name = revoking.name;
          startAct(async () => {
            const result = await revokeWgOnlyPeerAction(data);
            toastResult(result, {
              success: "Unmanaged peer revoked",
              successDescription: `${name} no longer reaches any device.`,
            });
            setRevoking(null);
            if (result.ok) router.refresh();
          });
        }}
      />
    </Section>
  );
}
