import type { ServiceCa } from "@/lib/coord-services";
import { EmptyState } from "../empty-state";
import { CopyButton } from "../ui/copy-button";
import { LocalTime } from "../ui/local-time";
import { MonoValue } from "../ui/mono-value";
import { Section } from "../ui/section";

export function ServiceCaPanel({ ca }: { ca: ServiceCa | null }) {
  return (
    <Section
      id="certificate-authority"
      title="Organisation service CA"
      description="A private certificate authority, limited to this organisation's service names, signs 24-hour certificates for serving devices. The serving device generates its own key; the coordinator only signs its request and never holds service keys. Trusting this CA on client devices is a manual step today."
      actions={
        ca ? (
          <a
            className="button secondary"
            href={`data:application/x-pem-file;charset=utf-8,${encodeURIComponent(ca.cert_pem)}`}
            download="blaktail-services-ca.pem"
          >
            Download CA certificate
          </a>
        ) : null
      }
    >
      {ca ? (
        <>
          <dl className="details">
            <div>
              <dt>SHA-256 fingerprint</dt>
              <dd>
                <MonoValue
                  value={ca.fingerprint_sha256}
                  wrap
                  copy
                  copyLabel="Copy CA fingerprint"
                />
              </dd>
            </div>
            <div>
              <dt>Expires</dt>
              <dd>
                <LocalTime value={ca.not_after} dateOnly />
              </dd>
            </div>
          </dl>
          <details>
            <summary>Show the CA certificate (PEM)</summary>
            <div className="stack pem-block">
              <textarea
                className="mono ca-pem"
                rows={10}
                readOnly
                value={ca.cert_pem}
                aria-label="CA certificate (PEM)"
              />
              <div className="actions">
                <CopyButton value={ca.cert_pem} label="Copy CA certificate" toastMessage="CA certificate copied" />
              </div>
            </div>
          </details>
        </>
      ) : (
        <EmptyState
          compact
          headingLevel={3}
          title="No CA yet"
          body="The CA is created with the first service in this organisation."
        />
      )}
    </Section>
  );
}
