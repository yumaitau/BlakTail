import type { ServiceCa } from "@/lib/coord-services";

export function ServiceCaPanel({ ca }: { ca: ServiceCa | null }) {
  return (
    <div className="panel stack" id="certificate-authority">
      <div>
        <h2>Organisation service CA</h2>
        <p className="muted">
          A private certificate authority, limited to this organisation&apos;s
          service names, signs 24-hour certificates for serving devices. The
          serving device generates its own key; the coordinator only signs
          its request and never holds service keys.
        </p>
        <p className="muted">
          Trusting this CA on client devices is a manual step today, and no
          serving agent listener ships yet, so installing it does not make any
          service reachable.
        </p>
      </div>
      {ca ? (
        <>
          <dl className="details">
            <div>
              <dt>SHA-256 fingerprint</dt>
              <dd className="mono">{ca.fingerprint_sha256}</dd>
            </div>
            <div>
              <dt>Expires</dt>
              <dd>
                {new Date(ca.not_after * 1000).toLocaleDateString("en-AU", {
                  dateStyle: "medium",
                })}
              </dd>
            </div>
          </dl>
          <label>
            CA certificate (PEM)
            <textarea className="mono" rows={10} readOnly value={ca.cert_pem} />
          </label>
          <div>
            <a
              className="button secondary"
              href={`data:application/x-pem-file;charset=utf-8,${encodeURIComponent(ca.cert_pem)}`}
              download="blaktail-services-ca.pem"
            >
              Download CA certificate
            </a>
          </div>
        </>
      ) : (
        <p className="muted">
          The CA is created with the first service in this organisation.
        </p>
      )}
    </div>
  );
}
