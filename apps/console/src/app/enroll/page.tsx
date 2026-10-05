import { errorText } from "@/lib/server-errors";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { ConsoleShell } from "@/components/console-shell";
import { EnrollmentApproval } from "@/components/enrollment-approval";
import Link from "next/link";
import { PageHeader } from "@/components/page-header";
import { StatusPage } from "@/components/status-page";
import { Alert } from "@/components/ui/alert";
import { MonoValue } from "@/components/ui/mono-value";
import { Section } from "@/components/ui/section";
import { auth } from "@/lib/auth";
import { getDeviceAuthorization } from "@/lib/coord";
import { requireConsoleContext } from "@/lib/session";

function deviceCode(value: string | string[] | undefined): string | null {
  const raw = Array.isArray(value) ? value[0] : value;
  const normalized = (raw ?? "")
    .toUpperCase()
    .replaceAll(/[^A-Z0-9]/g, "");
  if (!/^[A-Z0-9]{8}$/.test(normalized)) return null;
  return `${normalized.slice(0, 4)}-${normalized.slice(4)}`;
}

export default async function EnrollPage({
  searchParams,
}: {
  searchParams: Promise<{ code?: string | string[] }>;
}) {
  const code = deviceCode((await searchParams).code);
  if (!code) {
    return (
      <StatusPage
        code="Enrolment"
        title="This device link isn't valid"
        body={
          <>
            The link needs the eight-character code that{" "}
            <span className="mono nowrap">blaktaild up</span>{" "}
            prints. Run it again on the device and open the new link.
          </>
        }
        actions={
          <Link className="button secondary" href="/devices">
            Go to devices
          </Link>
        }
      />
    );
  }

  const session = await auth.api.getSession({ headers: await headers() });
  if (!session) {
    const next = `/enroll?code=${encodeURIComponent(code)}`;
    redirect(`/sign-in?next=${encodeURIComponent(next)}`);
  }
  const ctx = await requireConsoleContext();

  let request;
  let loadError: string | null = null;
  try {
    request = await getDeviceAuthorization(ctx, code);
  } catch (error) {
    loadError =
      errorText(error, "Could not load this device authorization.");
  }
  if (!request) {
    return (
      <ConsoleShell ctx={ctx} current="/devices">
        <div className="stack">
          <PageHeader eyebrow="Enrolment" title="Enrolment unavailable" />
          <Alert tone="error" title="This device request can't be opened">
            {loadError}
          </Alert>
          <p className="muted">
            The request may have expired. Run <span className="mono">blaktaild up</span> again on
            the device to get a fresh link.
          </p>
        </div>
      </ConsoleShell>
    );
  }

  return (
    <ConsoleShell ctx={ctx} current="/devices">
      <div className="stack">
        <PageHeader
          eyebrow="Enrolment"
          title="Approve device"
          description="Match the name and WireGuard fingerprint with the terminal before you approve. Approval lets this device onto the organisation network."
        />
        <ol className="ceremony" aria-label="Enrolment path">
          <li>Device</li>
          <li>Fingerprint</li>
          <li aria-current="step">Approve</li>
          <li>Joined</li>
        </ol>
        <Section
          id="device"
          title={request.name}
          description="Check these match what the terminal shows."
        >
          <dl className="details">
            <div>
              <dt>Device code</dt>
              <dd className="mono">{code}</dd>
            </div>
            <div>
              <dt>WireGuard key fingerprint</dt>
              <dd>
                <MonoValue value={request.public_key_fingerprint} wrap />
              </dd>
            </div>
            <div>
              <dt>Expires</dt>
              <dd>
                <time dateTime={new Date(request.expires_at * 1000).toISOString()}>
                  {new Date(request.expires_at * 1000).toLocaleString("en-AU", {
                    dateStyle: "medium",
                    timeStyle: "short",
                  })}
                </time>
              </dd>
            </div>
            <div>
              <dt>Organisation</dt>
              <dd>{ctx.organisationName}</dd>
            </div>
          </dl>
          <EnrollmentApproval
            code={code}
            role={ctx.role}
            alreadyApproved={request.approved}
          />
        </Section>
      </div>
    </ConsoleShell>
  );
}
