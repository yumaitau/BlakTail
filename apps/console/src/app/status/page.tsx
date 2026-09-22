import { ConsoleShell } from "@/components/console-shell";
import { PageHeader } from "@/components/page-header";
import { getCoordHealth } from "@/lib/coord";
import { requireConsoleContext } from "@/lib/session";

export default async function StatusPage() {
  const ctx = await requireConsoleContext();
  let health: Awaited<ReturnType<typeof getCoordHealth>> | null = null;
  let error: string | null = null;
  try {
    health = await getCoordHealth();
  } catch (err) {
    error =
      err instanceof Error ? err.message : "Could not reach the coordinator.";
  }

  return (
    <ConsoleShell ctx={ctx} current="/status">
      <div className="stack">
        <PageHeader
          title="Status"
          description="Health of the onshore coordinator that holds your tailnet state."
        />
        <div className="panel stack">
          {error ? (
            <>
              <p>
                <span className="badge revoked">Unreachable</span>
              </p>
              <p className="error" role="alert">
                {error}
              </p>
              <p className="muted">
                Check that the coordinator container is running and its TLS
                certificate is the one this console trusts, then reload this
                page. Devices keep their last approved configuration until the
                coordinator answers again.
              </p>
            </>
          ) : null}
          {health ? (
            <>
              <p>
                <span className="badge online">{health.status}</span>
              </p>
              <p className="region-mark">
                <span className="region-dot" aria-hidden="true" />
                <strong>Onshore</strong>
                <span>Sydney, Australia · AU · ap-southeast-2</span>
              </p>
              <p className="muted">
                This page only reports whether the coordinator is available.
                Device reachability stays on Devices. Region and component
                diagnostics stay in the protected operator configuration.
              </p>
            </>
          ) : null}
        </div>
      </div>
    </ConsoleShell>
  );
}
