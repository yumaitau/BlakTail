"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  addGroupMappingAction,
  applyDirectoryDriftAction,
  previewDirectoryDriftAction,
  removeGroupMappingAction,
  saveDirectorySettingsAction,
} from "@/app/settings/directory-actions";
import type { DriftPreview } from "@/lib/directory-mapping";
import type { DirectorySettings, GroupRoleMapping } from "@/lib/directory-mapping-core";
import { ORG_ROLES, roleLabel } from "@/lib/roles";

const SOURCE_LABEL = { scim: "SCIM group", oidc: "OIDC groups claim" } as const;

export function DirectoryRoleMapping({
  settings,
  mappings,
  organisationName,
}: {
  settings: DirectorySettings;
  mappings: GroupRoleMapping[];
  organisationName: string;
}) {
  const router = useRouter();
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [preview, setPreview] = useState<DriftPreview | null>(null);
  const roles = ORG_ROLES.filter((role) => role !== "owner" || settings.allowOwnerMapping);
  const applicable = preview?.changes.filter((change) => !change.blocked) ?? [];

  const run = (work: () => Promise<{ ok: boolean; error?: string }>, done?: string) => {
    setError(null);
    setNotice(null);
    startTransition(async () => {
      const result = await work();
      if (!result.ok) {
        setError(result.error ?? "The request failed.");
        return;
      }
      if (done) setNotice(done);
      setPreview(null);
      router.refresh();
    });
  };

  return (
    <section className="panel stack" aria-labelledby="directory-mapping-heading">
      <div>
        <h2 id="directory-mapping-heading">Directory group roles</h2>
        <p className="muted">
          Map identity-provider groups to roles in {organisationName}. The
          highest mapped role wins. Group changes never change a role on their
          own: preview the drift, then apply it. Owners are left alone and no
          change can remove the last password owner.
        </p>
      </div>
      <form
        className="stack"
        aria-label="Directory sync settings"
        onSubmit={(event) => {
          event.preventDefault();
          const form = new FormData(event.currentTarget);
          run(() => saveDirectorySettingsAction(form), "Directory settings saved.");
        }}
      >
        <div className="row">
          <label>
            Deprovision grace period (days)
            <input
              name="deprovisionGraceDays"
              type="number"
              min={0}
              max={90}
              required
              defaultValue={settings.deprovisionGraceDays}
            />
          </label>
          <label className="row">
            <input
              type="checkbox"
              name="allowOwnerMapping"
              defaultChecked={settings.allowOwnerMapping}
            />
            Allow a directory group to grant owner
          </label>
        </div>
        <p className="muted">
          A member the provider deactivates is suspended at once and kept for
          the grace period, then tombstoned (removed, record kept). Reactivating
          inside the grace period restores their role. Zero tombstones at once.
        </p>
        <div>
          <button type="submit" className="secondary" disabled={pending}>
            Save directory settings
          </button>
        </div>
      </form>
      <form
        className="row"
        aria-label="Add a group mapping"
        onSubmit={(event) => {
          event.preventDefault();
          const formEl = event.currentTarget;
          const form = new FormData(formEl);
          run(async () => {
            const result = await addGroupMappingAction(form);
            if (result.ok) formEl.reset();
            return result;
          }, "Mapping added. Preview to see who it affects.");
        }}
      >
        <label>
          Source
          <select name="source" defaultValue="scim">
            <option value="scim">{SOURCE_LABEL.scim}</option>
            <option value="oidc">{SOURCE_LABEL.oidc}</option>
          </select>
        </label>
        <label>
          Group name
          <input name="groupName" required maxLength={256} placeholder="BlakTail Admins" />
        </label>
        <label>
          Role
          <select name="role" defaultValue="member">
            {roles.map((role) => (
              <option key={role} value={role}>
                {roleLabel(role)}
              </option>
            ))}
          </select>
        </label>
        <button type="submit" disabled={pending}>
          Add mapping
        </button>
      </form>
      {mappings.length === 0 ? (
        <p className="muted">No group mappings. Roles stay as owners set them.</p>
      ) : (
        <div className="table-wrap">
          <table className="table">
            <thead>
              <tr>
                <th>Source</th>
                <th>Group</th>
                <th>Role</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {mappings.map((mapping) => (
                <tr key={mapping.id}>
                  <td>{SOURCE_LABEL[mapping.source]}</td>
                  <td className="mono">{mapping.groupName}</td>
                  <td>{roleLabel(mapping.role)}</td>
                  <td>
                    <button
                      type="button"
                      className="danger"
                      disabled={pending}
                      onClick={() => {
                        const form = new FormData();
                        form.set("mappingId", mapping.id ?? "");
                        run(() => removeGroupMappingAction(form), "Mapping removed.");
                      }}
                    >
                      Remove
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div>
        <button
          type="button"
          className="secondary"
          disabled={pending}
          onClick={() => {
            setError(null);
            setNotice(null);
            startTransition(async () => {
              const result = await previewDirectoryDriftAction();
              if (!result.ok) {
                setError(result.error);
                return;
              }
              setPreview(result.data);
            });
          }}
        >
          {pending ? "Working…" : "Preview role changes"}
        </button>
      </div>
      {error ? (
        <p className="error" role="alert">
          {error}
        </p>
      ) : null}
      {notice ? (
        <p className="muted" role="status">
          {notice}
        </p>
      ) : null}
      {preview ? (
        <div className="stack">
          <h3>Drift preview</h3>
          {preview.changes.length === 0 ? (
            <p className="muted">Everyone already holds the role their groups map to.</p>
          ) : (
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr>
                    <th>Person</th>
                    <th>Change</th>
                    <th>Because of</th>
                    <th>Outcome</th>
                  </tr>
                </thead>
                <tbody>
                  {preview.changes.map((change) => (
                    <tr key={change.membershipId}>
                      <td>{change.email}</td>
                      <td>
                        {roleLabel(change.from)} → {roleLabel(change.to)}
                      </td>
                      <td className="mono">
                        {change.groups.length ? change.groups.join(", ") : "no mapped group (back to member)"}
                      </td>
                      <td>
                        {change.blocked ? (
                          <span className="badge warn">Blocked: {change.blocked}</span>
                        ) : (
                          "Will change"
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {applicable.length > 0 ? (
            <div>
              <button
                type="button"
                disabled={pending}
                onClick={() => {
                  const form = new FormData();
                  form.set("signature", preview.signature);
                  run(
                    () => applyDirectoryDriftAction(form),
                    `Applied ${applicable.length} role change${applicable.length === 1 ? "" : "s"}.`,
                  );
                }}
              >
                Apply {applicable.length} change{applicable.length === 1 ? "" : "s"}
              </button>
            </div>
          ) : null}
          {preview.deprovisioned.length > 0 ? (
            <>
              <h3>Deprovisioned members</h3>
              <ul>
                {preview.deprovisioned.map((row) => (
                  <li key={row.membershipId}>
                    {row.email} ({roleLabel(row.role)}):{" "}
                    {row.state === "tombstoned"
                      ? `tombstoned ${row.tombstonedAt?.slice(0, 10) ?? ""}`
                      : `suspended, tombstone after ${row.deprovisionAt?.slice(0, 10) ?? ""}`}
                  </li>
                ))}
              </ul>
            </>
          ) : null}
        </div>
      ) : null}
    </section>
  );
}
