"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  createWgOnlyPeerAction,
  rotateWgOnlyPeerAction,
  revokeWgOnlyPeerAction,
} from "@/app/actions";
import { ACL_TAGS } from "@/lib/acl";
import { can, type OrgRole } from "@/lib/roles";
import type { NetworkWgOnlyPeer } from "@/lib/coord";

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
  const canMutate = can(role, "manage_peers");
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  return (
    <div className="panel stack">
      <div>
        <h2>Unmanaged WireGuard peers</h2>
        <p className="muted">
          Public-key-only endpoints. BlakTail never stores the private key.
          Policy on managed agents decides who receives the peer. Kind is
          always <span className="mono">wireguard_only</span>.
        </p>
      </div>
      {errors.map((item) => (
        <p className="error" key={item}>
          {item}
        </p>
      ))}
      {canMutate ? (
        <form
          onSubmit={(event) => {
            event.preventDefault();
            const form = event.currentTarget;
            const data = new FormData(form);
            data.set("organisationId", organisationId);
            setError(null);
            startTransition(async () => {
              const result = await createWgOnlyPeerAction(data);
              if (!result.ok) {
                setError(result.error);
                return;
              }
              form.reset();
              router.refresh();
            });
          }}
        >
          <label>
            Name
            <input name="name" required maxLength={64} placeholder="printer" />
          </label>
          <label>
            Public key
            <input
              className="mono"
              name="wgPublicKey"
              required
              placeholder="base64 WireGuard public key"
            />
          </label>
          <label>
            Endpoint
            <input
              className="mono"
              name="endpoint"
              required
              placeholder="203.0.113.10:51820"
            />
          </label>
          <label>
            AllowedIPs
            <input
              className="mono"
              name="allowedIps"
              required
              placeholder="10.0.0.10/32"
            />
          </label>
          <fieldset>
            <legend>Tags</legend>
            {ACL_TAGS.map((tag) => (
              <label key={tag} className="route-option">
                <input type="checkbox" name="tags" value={tag} />
                {tag}
              </label>
            ))}
          </fieldset>
          <button type="submit" disabled={pending} data-testid="wg-only-add">
            {pending ? "Adding…" : "Add unmanaged peer"}
          </button>
        </form>
      ) : (
        <p className="muted">Members can see unmanaged peers but cannot add, rotate, or revoke them.</p>
      )}
      {error ? <p className="error">{error}</p> : null}
      {peers.length ? (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Kind</th>
                <th>Endpoint</th>
                <th>AllowedIPs</th>
                <th>State</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {peers.map((peer) => (
                <tr key={peer.id}>
                  <td>
                    {peer.name}
                    <div className="muted">{peer.organisation_name}</div>
                  </td>
                  <td className="mono">{peer.kind}</td>
                  <td className="mono">{peer.endpoint}</td>
                  <td className="mono">{peer.allowed_ips.join(", ")}</td>
                  <td>
                    <span
                      className={
                        peer.revoked_at ? "badge revoked" : "badge online"
                      }
                    >
                      {peer.revoked_at ? "Revoked" : "Unmanaged"}
                    </span>
                    {peer.previous_wg_public_key && peer.overlap_until ? (
                      <div className="muted">
                        Overlap until {peer.overlap_until}
                      </div>
                    ) : null}
                  </td>
                  <td>
                    {canMutate && !peer.revoked_at ? (
                      <div className="stack">
                        <form
                          onSubmit={(event) => {
                            event.preventDefault();
                            const form = event.currentTarget;
                            const data = new FormData(form);
                            data.set("peerId", peer.id);
                            data.set("organisationId", peer.organisation_id);
                            setError(null);
                            startTransition(async () => {
                              const result = await rotateWgOnlyPeerAction(data);
                              if (!result.ok) {
                                setError(result.error);
                                return;
                              }
                              form.reset();
                              router.refresh();
                            });
                          }}
                        >
                          <input
                            className="mono"
                            name="wgPublicKey"
                            required
                            placeholder="new public key"
                            aria-label={`Rotate ${peer.name} public key`}
                          />
                          <input
                            type="hidden"
                            name="overlapSeconds"
                            value="300"
                          />
                          <button type="submit" disabled={pending} data-testid="wg-only-rotate">
                            Rotate
                          </button>
                        </form>
                        <button
                          type="button"
                          className="danger"
                          disabled={pending}
                          onClick={() => {
                            const form = new FormData();
                            form.set("peerId", peer.id);
                            form.set("organisationId", peer.organisation_id);
                            startTransition(async () => {
                              const result = await revokeWgOnlyPeerAction(form);
                              if (!result.ok) {
                                setError(result.error);
                                return;
                              }
                              router.refresh();
                            });
                          }}
                        >
                          Revoke
                        </button>
                      </div>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <p className="muted">No unmanaged WireGuard peers yet.</p>
      )}
    </div>
  );
}
