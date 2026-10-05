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
import { EmptyState } from "../empty-state";
import { Alert } from "../ui/alert";
import { StatusPill, type BadgeTone } from "../ui/badge";
import { Button } from "../ui/button";
import { ConfirmDialog } from "../ui/confirm-dialog";
import { FormField } from "../ui/form-field";
import { LocalTime } from "../ui/local-time";
import { MonoValue } from "../ui/mono-value";
import { Section } from "../ui/section";
import { Table, Td } from "../ui/table";
import { toastResult } from "../ui/toast";

const TAGS: DeviceTag[] = ["office", "ranger", "store"];

const STATUS: Record<ServiceStatus, { label: string; tone: BadgeTone }> = {
  disabled: { label: "Disabled", tone: "muted" },
  target_unavailable: { label: "Target unavailable", tone: "danger" },
  awaiting_certificate: { label: "Awaiting certificate", tone: "warning" },
  certificate_issued: { label: "Certificate issued, not serving", tone: "warning" },
  target_unhealthy: { label: "Target unhealthy", tone: "danger" },
  serving: { label: "Serving", tone: "success" },
};

export function ServiceManager({
  services,
  devices,
  namespace,
  readOnlyReason,
}: {
  services: PrivateService[];
  devices: { id: string; label: string }[];
  namespace: string;
  readOnlyReason: string | null;
}) {
  const router = useRouter();
  const formRef = useRef<HTMLFormElement>(null);
  const [pending, startTransition] = useTransition();
  const [busy, setBusy] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [preview, setPreview] = useState<ServicePreview | null>(null);
  const [deleting, setDeleting] = useState<PrivateService | null>(null);
  const canManage = readOnlyReason === null;

  function toggle(service: PrivateService) {
    setBusy(`toggle:${service.id}`);
    startTransition(async () => {
      const result = await setServiceEnabledAction(service.id, service.revision, !service.enabled);
      setBusy(null);
      toastResult(result, {
        success: service.enabled ? "Service disabled" : "Service enabled",
        successDescription: service.enabled
          ? `${service.fqdn} is withdrawn from devices.`
          : `${service.fqdn} is offered again once the device reports it healthy.`,
      });
      if (result.ok) router.refresh();
    });
  }

  return (
    <>
      <Section
        id="services"
        title="Services"
        description={
          <>
            Each service gets a name under <span className="mono">{namespace}</span>, separate
            from device MagicDNS names. The target device serves it after{" "}
            <span className="mono">blaktaild up --serve-services</span>; the name reaches devices
            with an allowed tag only while that device reports a current certificate and a healthy
            local target. Status refreshes about every 30 seconds.
          </>
        }
      >
        {services.length === 0 ? (
          <EmptyState
            compact
            headingLevel={3}
            title="No private services yet"
            body="Create one below to give a web app on one of your devices a private HTTPS name."
          />
        ) : (
          <Table label="Private services" mobile="stack">
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
                    <Td label="Service">
                      <div>
                        <div className="device-primary">{service.name}</div>
                        <MonoValue value={service.fqdn} copy copyLabel={`Copy ${service.name} address`} />
                        {service.description ? (
                          <div className="cell-sub">{service.description}</div>
                        ) : null}
                      </div>
                    </Td>
                    <Td label="Target">
                      <div>
                        {service.target_node_name ?? "Removed device"}
                        {service.target_node_available ? "" : " (unavailable)"}
                        <div className="cell-sub">
                          Local {service.protocol.toUpperCase()} port{" "}
                          <span className="mono">{service.port}</span>
                        </div>
                      </div>
                    </Td>
                    <Td label="Access tags">
                      {service.access_tags.length > 0 ? (
                        <span className="tag-list">
                          {service.access_tags.map((tag) => (
                            <StatusPill key={tag} dot={false}>
                              {tag}
                            </StatusPill>
                          ))}
                        </span>
                      ) : (
                        <span className="muted">None</span>
                      )}
                    </Td>
                    <Td label="Status">
                      <div>
                        <StatusPill tone={status.tone}>{status.label}</StatusPill>
                        <div className="cell-sub">{service.status_detail}</div>
                        {service.certificate ? (
                          <div className="cell-sub">
                            Certificate expires <LocalTime value={service.certificate.not_after} />
                          </div>
                        ) : null}
                      </div>
                    </Td>
                    <Td>
                      {canManage ? (
                        <div className="cell-actions">
                          <Button
                            variant="secondary"
                            size="sm"
                            disabled={pending}
                            loading={busy === `toggle:${service.id}`}
                            onClick={() => toggle(service)}
                          >
                            {service.enabled ? "Disable" : "Enable"}
                          </Button>
                          <Button
                            variant="quiet-danger"
                            size="sm"
                            disabled={pending}
                            onClick={() => setDeleting(service)}
                          >
                            Delete
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

      {canManage ? (
        <Section
          id="create"
          title="Create a service"
          description="Preview first to see the full name and any collisions."
        >
          {devices.length === 0 ? (
            <Alert tone="info" title="Enrol a device first">
              A service needs a target device that will serve it.
            </Alert>
          ) : (
            <form
              ref={formRef}
              className="ui-form wide"
              noValidate
              onChange={() => setPreview(null)}
              onSubmit={(event) => {
                event.preventDefault();
                const form = new FormData(event.currentTarget);
                setBusy("create");
                startTransition(async () => {
                  if (!preview) {
                    const result = await previewServiceAction(form);
                    setBusy(null);
                    setFieldErrors(toastResult(result, { errorToast: false }));
                    if (result.ok) setPreview(result.data);
                    return;
                  }
                  const result = await createServiceAction(form);
                  setBusy(null);
                  setFieldErrors(
                    toastResult(result, {
                      success: "Service created",
                      successDescription: preview.fqdn ?? undefined,
                      errorToast: false,
                    }),
                  );
                  if (!result.ok) return;
                  setPreview(null);
                  formRef.current?.reset();
                  router.refresh();
                });
              }}
            >
              <div className="ui-form-grid">
                <FormField
                  label="Name"
                  required
                  hint="3 to 63 lowercase letters, digits or hyphens."
                  error={fieldErrors.name}
                >
                  <input
                    name="name"
                    maxLength={63}
                    autoComplete="off"
                    spellCheck={false}
                    placeholder="wiki"
                    disabled={pending}
                  />
                </FormField>
                <FormField label="Target device" required error={fieldErrors.targetNodeId}>
                  <select name="targetNodeId" disabled={pending}>
                    {devices.map((device) => (
                      <option key={device.id} value={device.id}>
                        {device.label}
                      </option>
                    ))}
                  </select>
                </FormField>
              </div>
              <div className="ui-form-grid">
                <FormField label="Local port on the target" required error={fieldErrors.port}>
                  <input
                    name="port"
                    type="number"
                    min={1}
                    max={65535}
                    defaultValue={8080}
                    disabled={pending}
                  />
                </FormField>
                <FormField label="Local protocol">
                  <select name="protocol" defaultValue="http" disabled={pending}>
                    <option value="http">HTTP</option>
                    <option value="https">HTTPS (not served yet)</option>
                  </select>
                </FormField>
              </div>
              <fieldset className="ui-fieldset" disabled={pending}>
                <legend>Devices allowed to use it (by tag)</legend>
                <div className="ui-choices">
                  {TAGS.map((tag) => (
                    <label key={tag}>
                      <input type="checkbox" name="accessTags" value={tag} />
                      {tag}
                    </label>
                  ))}
                </div>
              </fieldset>
              <FormField
                label="Description"
                hint="Optional. What the service is for."
                error={fieldErrors.description}
                className="field-lg"
              >
                <input name="description" maxLength={200} disabled={pending} />
              </FormField>
              {preview ? (
                <Alert
                  tone={preview.valid ? "success" : "error"}
                  title={preview.valid ? "Ready to create" : "This service can't be created yet"}
                >
                  <p>
                    Full name:{" "}
                    {preview.fqdn ? <MonoValue value={preview.fqdn} /> : "not available"}
                  </p>
                  {preview.problems.length > 0 ? (
                    <ul>
                      {preview.problems.map((problem) => (
                        <li key={problem}>{problem}</li>
                      ))}
                    </ul>
                  ) : null}
                  {preview.warnings.length > 0 ? (
                    <ul>
                      {preview.warnings.map((warning) => (
                        <li key={warning}>Warning: {warning}</li>
                      ))}
                    </ul>
                  ) : null}
                </Alert>
              ) : null}
              <div className="ui-form-actions">
                <Button
                  type="submit"
                  loading={busy === "create"}
                  loadingLabel={preview ? "Creating…" : "Checking…"}
                  disabled={pending || (preview !== null && !preview.valid)}
                >
                  {preview ? "Create service" : "Preview"}
                </Button>
                {preview ? (
                  <Button variant="secondary" disabled={pending} onClick={() => setPreview(null)}>
                    Edit details
                  </Button>
                ) : null}
              </div>
            </form>
          )}
        </Section>
      ) : null}

      <ConfirmDialog
        open={deleting !== null}
        title="Delete private service"
        description={
          deleting
            ? `${deleting.fqdn} stops resolving on every device and its certificates are revoked. This can't be undone.`
            : null
        }
        confirmText={deleting?.name}
        confirmLabel="Delete service"
        pending={busy === "delete"}
        onCancel={() => setDeleting(null)}
        onConfirm={() => {
          if (!deleting) return;
          const service = deleting;
          setBusy("delete");
          startTransition(async () => {
            const result = await deleteServiceAction(service.id);
            setBusy(null);
            toastResult(result, {
              success: "Service deleted",
              successDescription: `${service.fqdn} no longer resolves.`,
            });
            setDeleting(null);
            if (result.ok) router.refresh();
          });
        }}
      />
    </>
  );
}
