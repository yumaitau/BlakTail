import Link from "next/link";
import { EmptyState } from "@/components/empty-state";
import { StatusPill, type BadgeTone } from "@/components/ui/badge";
import { Table, Td } from "@/components/ui/table";
import { protectionLabel, type PqPeerProtection } from "@/lib/coord-pq";

const TONE: Record<string, BadgeTone> = {
  online: "success",
  warn: "danger",
  offline: "muted",
  "": "neutral",
};

const MODE_LABEL: Record<string, string> = {
  off: "Off",
  prefer: "Prefer",
  require: "Require",
};

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
        compact
        headingLevel={3}
        title="No reports yet"
        body="Agents report per-peer protection once the organisation policy is prefer or require. Until then every tunnel is classical WireGuard."
      />
    );
  }
  return (
    <>
      <p className="muted small">
        Reported by the agent on each device. Stale means no report for five minutes.
      </p>
      <Table label="Per-peer tunnel protection" mobile="stack">
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
                  <Td label="Device">
                    <Link href={`/devices/${row.node_id}`}>
                      {deviceNames?.get(row.node_id) ?? row.node_id}
                    </Link>
                  </Td>
                ) : null}
                <Td label="Peer">
                  <Link href={`/devices/${row.peer_id}`}>{row.peer_name}</Link>
                </Td>
                <Td label="Protection">
                  <div>
                    <StatusPill tone={TONE[shown.tone] ?? "neutral"}>{shown.label}</StatusPill>
                    {row.stale ? <div className="cell-sub">Stale report</div> : null}
                  </div>
                </Td>
                <Td label="Policy">{MODE_LABEL[row.mode] ?? row.mode}</Td>
                <Td label="Detail" className="muted">
                  {shown.detail}
                </Td>
              </tr>
            );
          })}
        </tbody>
      </Table>
    </>
  );
}
