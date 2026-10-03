import Link from "next/link";
import { EmptyState } from "@/components/empty-state";
import { protectionLabel, type PqPeerProtection } from "@/lib/coord-pq";

/** Per-peer negotiated protection, as each agent reported it. */
export function PqPeerTable({
  rows,
  deviceNames,
  showDevice = false,
}: {
  rows: PqPeerProtection[];
  deviceNames?: Map<string, string>;
  showDevice?: boolean;
}) {
  if (rows.length === 0) {
    return (
      <EmptyState
        title="No reports yet"
        body="Agents report per-peer protection once the organisation policy is prefer or require. Until then every tunnel is classical WireGuard."
      />
    );
  }
  return (
    <div className="table-wrap">
      <table className="table">
        <caption className="muted">
          Reported by the agent on each device. Stale means no report for five minutes.
        </caption>
        <thead>
          <tr>
            {showDevice ? <th scope="col">Device</th> : null}
            <th scope="col">Peer</th>
            <th scope="col">Protection</th>
            <th scope="col">Policy</th>
            <th scope="col">Detail</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const shown = protectionLabel(row);
            return (
              <tr key={`${row.node_id}-${row.peer_id}`}>
                {showDevice ? (
                  <td>
                    <Link href={`/devices/${row.node_id}`}>
                      {deviceNames?.get(row.node_id) ?? row.node_id}
                    </Link>
                  </td>
                ) : null}
                <td>
                  <Link href={`/devices/${row.peer_id}`}>{row.peer_name}</Link>
                </td>
                <td>
                  <span className={shown.tone ? `badge ${shown.tone}` : "badge"}>{shown.label}</span>
                  {row.stale ? <div className="muted">Stale report</div> : null}
                </td>
                <td>{row.mode}</td>
                <td className="muted">{shown.detail}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
