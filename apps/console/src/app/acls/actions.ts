"use server";

import { actionFailure } from "@/lib/server-errors";
import type { DeviceTag } from "@/lib/coord";
import {
  explainAccess,
  type ExplainProtocol,
  type ExplainRequest,
  type ExplainResult,
} from "@/lib/coord-policy";
import { requireConsoleContext } from "@/lib/session";

export type ExplainActionResult =
  | { ok: true; data: ExplainResult }
  | { ok: false; error: string };

export type ExplainForm = {
  sourceMode: "device" | "person";
  sourceNodeId: string;
  sourceUser: string;
  sourceRole: string;
  sourceTags: string[];
  destinationNodeId: string;
  protocol: string;
  port: string;
  sshUser: string;
};

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/iu;
const TAGS: DeviceTag[] = ["office", "ranger", "store"];

// Members may explain: the coordinator only reads the published policy.
export async function explainAccessAction(form: ExplainForm): Promise<ExplainActionResult> {
  try {
    const ctx = await requireConsoleContext();
    if (!UUID.test(form.destinationNodeId)) {
      return { ok: false, error: "Choose a destination device." };
    }
    const input: ExplainRequest = { destination_node_id: form.destinationNodeId };
    if (form.sourceMode === "device") {
      if (!UUID.test(form.sourceNodeId)) {
        return { ok: false, error: "Choose a source device." };
      }
      input.source_node_id = form.sourceNodeId;
    } else {
      const role = ["owner", "admin", "member"].includes(form.sourceRole)
        ? (form.sourceRole as "owner" | "admin" | "member")
        : "member";
      input.source = {
        user: form.sourceUser.trim(),
        role,
        tags: form.sourceTags.filter((tag): tag is DeviceTag => TAGS.includes(tag as DeviceTag)),
      };
    }
    const sshUser = form.sshUser.trim();
    if (sshUser) {
      if (!/^[A-Za-z_][A-Za-z0-9._-]{0,31}$/u.test(sshUser)) {
        return { ok: false, error: "SSH user must be a plain login name." };
      }
      input.ssh_user = sshUser;
    } else {
      if (["tcp", "udp", "icmp"].includes(form.protocol)) {
        input.protocol = form.protocol as ExplainProtocol;
      }
      const port = form.port.trim();
      if (port) {
        const value = Number.parseInt(port, 10);
        if (!Number.isInteger(value) || value < 1 || value > 65535 || String(value) !== port) {
          return { ok: false, error: "Port must be a number from 1 to 65535." };
        }
        if (input.protocol === "icmp") {
          return { ok: false, error: "ICMP has no port. Clear the port or pick TCP or UDP." };
        }
        input.port = value;
      }
    }
    return { ok: true, data: await explainAccess(ctx, input) };
  } catch (error) {
    return actionFailure(error, "Could not explain access.");
  }
}
