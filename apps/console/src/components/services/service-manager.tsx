"use client";

import { useRef, useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import {
  createServiceAction,
  deleteServiceAction,
  previewServiceAction,
  setServiceEnabledAction,
} from "@/app/services/actions";
import type { DeviceTag } from "@/lib/coord";
import type {
  PrivateService,
  ServicePreview,
  ServiceStatus,
} from "@/lib/coord-services";

const TAGS: DeviceTag[] = ["office", "ranger", "store"];

const STATUS: Record<ServiceStatus, { label: string; tone: string }> = {
  disabled: { label: "Disabled", tone: "offline" },
  target_unavailable: { label: "Target unavailable", tone: "warn" },
  awaiting_serving_agent: { label: "Awaiting serving agent", tone: "pending" },
  certificate_issued: { label: "Certificate issued, not verified", tone: "pending" },
};

function when(seconds: number): string {
  return new Date(seconds * 1000).toLocaleString("en-AU", {
    dateStyle: "medium",
    timeStyle: "short",
  });
}

export function ServiceManager({
  services,
  devices,
  namespace,
  organisationName,
  roleLabel,
  readOnlyReason,
}: {
  services: PrivateService[];
  devices: { id: string; label: string }[];
  namespace: string;
  organisationName: string;
  roleLabel: string;
  readOnlyReason: string | null;
}) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [pending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<ServicePreview | null>(null);
  const disabled = readOnlyReason !== null || pending;

  function run(action: () => Promise<{ ok: true } | { ok: false; error: string }>) {
    setError(null);
    startTransition(async () => {
      const result = await action();
      if (!result.ok) {
        setError(result.error);
        return;
      }
      router.refresh();
    });
  }

  return (
    <div className="stack">
      <div className="panel stack" id="services">
        <div>
          <h2>Services</h2>
          <p className="muted">
            Each service gets a name under{" "}
            <span className="mono">{namespace}</span>, separate from device
            MagicDNS names. No serving agent listener ships yet, so services
            are not published in DNS and cannot be reached; the status shows
            what is still missing.
          </p>
        </div>
        {error ? (
          <p className="error" role="alert">
            {error}
          </p>
        ) : null}
        {services.length === 0 ? (
          <p className="muted">No private services yet.</p>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Service</th>
                  <th scope="col">Target</th>
                  <th scope="col">Access tags</th>
                  <th scope="col">Status</th>
                  <th scope="col">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {services.map((service) => {
                  const status = STATUS[service.status];
                  return (
                    <tr key={service.id}>
                      <td>
                        <div className="device-primary">{service.name}</div>
                        <div className="mono muted">{service.fqdn}</div>
                        {service.description ? (
                          <div className="muted">{service.description}</div>
                        ) : null}
                      </td>
                      <td>
                        {service.target_node_name ?? "Removed device"}
                        {service.target_node_available ? "" : " (unavailable)"}
                        <div className="muted">
                          Local {service.protocol.toUpperCase()} port{" "}
                          <span className="mono">{service.port}</span>
                        </div>
                      </td>
                      <td>
                        {service.access_tags.length > 0
                          ? service.access_tags.join(", ")
                          : "None"}
                      </td>
                      <td>
                        <span className={`badge ${status.tone}`}>{status.label}</span>
                        <div className="muted">{service.status_detail}</div>
                        {service.certificate ? (
                          <div className="muted">
                            Certificate expires {when(service.certificate.not_after)}
                          </div>
                        ) : null}
                      </td>
                      <td>
                        <div className="row">
                          <button
                            type="button"
                            className="secondary"
                            disabled={disabled}
                            title={readOnlyReason ?? undefined}
                            onClick={() =>
                              run(() =>
                                setServiceEnabledAction(
                                  service.id,
                                  service.revision,
                                  !service.enabled,
                                ),
                              )
                            }
                          >
                            {service.enabled ? "Disable" : "Enable"}
                          </button>
                          <button
                            type="button"
                            className="quiet-danger"
                            disabled={disabled}
                            title={readOnlyReason ?? undefined}
                            onClick={() => {
                              if (
                                window.confirm(
                                  `Delete ${service.name}? Issued certificates are revoked.`,
                                )
                              ) {
                                run(() => deleteServiceAction(service.id));
                              }
                            }}
                          >
                            Delete
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <div className="panel stack" id="create">
        <div>
          <h2>Create a service</h2>
          <p className="muted">
            Creating in <span className="badge network">{organisationName}</span>{" "}
            as {roleLabel}. Preview first to see the full name and any
            collisions.
          </p>
          {readOnlyReason ? <p className="muted">{readOnlyReason}</p> : null}
        </div>
        {devices.length === 0 ? (
          <p className="muted">
            Enrol a device first: a service needs a target device that will
            serve it.
          </p>
        ) : null}
        <form
          ref={formRef}
          className="stack"
          onChange={() => setPreview(null)}
          onSubmit={(event) => {
            event.preventDefault();
            const form = new FormData(event.currentTarget);
            setError(null);
            startTransition(async () => {
              if (!preview) {
                const result = await previewServiceAction(form);
                if (!result.ok) {
                  setError(result.error);
                  return;
                }
                setPreview(result.data);
                return;
              }
              const result = await createServiceAction(form);
              if (!result.ok) {
                setError(result.error);
                return;
              }
              setPreview(null);
              formRef.current?.reset();
              router.refresh();
            });
          }}
        >
          <div className="dns-grid">
            <label>
              Name
              <input
                name="name"
                required
                minLength={3}
                maxLength={63}
                pattern="[a-z0-9]([a-z0-9-]*[a-z0-9])?"
                title="3-63 lowercase letters, digits or hyphens; start and end with a letter or digit"
                disabled={disabled}
              />
            </label>
            <label>
              Target device
              <select name="targetNodeId" required disabled={disabled || devices.length === 0}>
                {devices.map((device) => (
                  <option key={device.id} value={device.id}>
                    {device.label}
                  </option>
                ))}
              </select>
            </label>
            <label>
              Local port on the target
              <input
                name="port"
                type="number"
                min={1}
                max={65535}
                required
                defaultValue={8080}
                disabled={disabled}
              />
            </label>
            <label>
              Local protocol
              <select name="protocol" defaultValue="http" disabled={disabled}>
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
              </select>
            </label>
          </div>
          <fieldset className="dns-assign">
            <legend>Devices allowed to use it (by tag)</legend>
            {TAGS.map((tag) => (
              <label key={tag}>
                <input type="checkbox" name="accessTags" value={tag} disabled={disabled} />
                {tag}
              </label>
            ))}
          </fieldset>
          <label>
            Description
            <input name="description" maxLength={200} disabled={disabled} />
          </label>
          {preview ? (
            <div className="stack" role="status">
              <p>
                Full name:{" "}
                <span className="mono">{preview.fqdn ?? "not available"}</span>
              </p>
              {preview.problems.length > 0 ? (
                <ul>
                  {preview.problems.map((problem) => (
                    <li key={problem} className="error">
                      {problem}
                    </li>
                  ))}
                </ul>
              ) : null}
              {preview.warnings.length > 0 ? (
                <ul>
                  {preview.warnings.map((warning) => (
                    <li key={warning}>
                      <span className="badge pending">Warning</span> {warning}
                    </li>
                  ))}
                </ul>
              ) : null}
            </div>
          ) : null}
          <div className="row">
            <button
              type="submit"
              disabled={disabled || devices.length === 0 || (preview !== null && !preview.valid)}
              title={readOnlyReason ?? undefined}
            >
              {pending ? "Working…" : preview ? "Create service" : "Preview"}
            </button>
            {preview ? (
              <button
                type="button"
                className="secondary"
                disabled={pending}
                onClick={() => setPreview(null)}
              >
                Edit details
              </button>
            ) : null}
          </div>
        </form>
      </div>
    </div>
  );
}
