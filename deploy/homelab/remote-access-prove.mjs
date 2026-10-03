// Lab driver for prove-remote-access.sh. Talks to the coordinator with
// signed console assertions (as the console would) and to the gateway over
// WebSocket (as the browser terminal would). Node 22+, no dependencies.
import { createHmac, randomUUID } from "node:crypto";

const COORD = process.env.LAB_COORD ?? "https://coord:8443";
const SECRET = process.env.LAB_HMAC_SECRET;
const OWNER = "lab-owner";
if (!SECRET) throw new Error("LAB_HMAC_SECRET is required");

function assertion(orgId, { sub = OWNER, role = "owner", action } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    sub,
    org_id: orgId,
    role,
    name: sub,
    email: `${sub}@lab.invalid`,
    iss: "blaktail-console",
    aud: "blaktail-coord",
    iat: now,
    exp: now + 60,
    jti: randomUUID(),
  };
  if (action) claims.action = action;
  const payload = Buffer.from(JSON.stringify(claims)).toString("base64url");
  const signature = createHmac("sha256", SECRET).update(payload).digest("base64url");
  return `${payload}.${signature}`;
}

async function api(method, path, { orgId, body, ...who } = {}) {
  const response = await fetch(`${COORD}${path}`, {
    method,
    headers: {
      authorization: `Bearer ${assertion(orgId, who)}`,
      "content-type": "application/json",
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await response.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  return { status: response.status, body: json };
}

function must(result, status, label) {
  if (result.status !== status) {
    throw new Error(`${label}: expected ${status}, got ${result.status} ${JSON.stringify(result.body)}`);
  }
  return result.body;
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function bootstrap() {
  const orgId = randomUUID();
  must(
    await api("POST", "/v1/orgs", {
      orgId,
      sub: "operator-cli",
      role: "service",
      action: "bootstrap.prepare",
      body: { id: orgId, name: "remote-access-lab", acl: { version: 1, defaults: "same_tag", rules: [] } },
    }),
    202,
    "prepare org",
  );
  must(
    await api("POST", `/v1/orgs/${orgId}/bootstrap-commit`, {
      orgId,
      sub: "operator-cli",
      role: "service",
      action: "bootstrap.commit",
      body: {},
    }),
    201,
    "commit org",
  );
  const keys = [];
  for (let index = 0; index < 2; index += 1) {
    const key = must(
      await api("POST", `/v1/orgs/${orgId}/join-keys`, { orgId, body: { expires_in_seconds: 600 } }),
      201,
      "mint join key",
    );
    keys.push(key.key);
  }
  console.log(`org=${orgId}\ngateway_key=${keys[0]}\ntarget_key=${keys[1]}`);
}

async function nodes(orgId) {
  return must(await api("GET", `/v1/orgs/${orgId}/nodes`, { orgId }), 200, "list nodes");
}

async function nodeByName(orgId, name) {
  const node = (await nodes(orgId)).find((candidate) => candidate.name === name);
  if (!node) throw new Error(`no node named ${name}`);
  return node;
}

async function configure(orgId) {
  must(
    await api("PUT", `/v1/orgs/${orgId}/acl`, {
      orgId,
      body: {
        defaults: "deny",
        groups: { crew: [OWNER] },
        rules: [
          { action: "allow", src_groups: ["crew"], dst_groups: ["crew"], dst_ports: ["22"], protocols: ["tcp"] },
        ],
        ssh: [{ action: "allow", src_groups: ["crew"], dst_groups: ["crew"], users: ["deploy"] }],
      },
    }),
    204,
    "put acl",
  );
  const gateway = await nodeByName(orgId, "lab-gateway");
  const settings = must(
    await api("PUT", `/v1/orgs/${orgId}/remote-access/settings`, {
      orgId,
      body: { gateway_node_id: gateway.id, gateway_url: "wss://gateway:8443" },
    }),
    200,
    "save gateway",
  );
  console.log(`ok gateway ${gateway.id} configured; CA ${settings.ca_public_key.slice(0, 40)}…`);
}

async function waitReady(orgId) {
  const deadline = Date.now() + 120_000;
  let last = "";
  while (Date.now() < deadline) {
    const target = await nodeByName(orgId, "lab-target");
    const keys = must(await api("GET", `/v1/orgs/${orgId}/remote-access/host-keys`, { orgId }), 200, "host keys");
    const key = keys.find((row) => row.node_id === target.id);
    const caps = target.capabilities ?? [];
    last = `capabilities=${caps.join(",")} host_key=${key?.fingerprint ?? "none"}`;
    if (caps.includes("remote-ssh-ca") && caps.includes("ssh-users") && caps.includes("remote-jobs") && key) {
      console.log(`ok target ready: ${last}`);
      return;
    }
    await sleep(3000);
  }
  throw new Error(`target never became ready: ${last}`);
}

async function issue(orgId, osUser = "deploy") {
  const target = await nodeByName(orgId, "lab-target");
  return api("POST", `/v1/orgs/${orgId}/remote-access/sessions`, {
    orgId,
    sub: "lab-admin",
    role: "admin",
    body: { kind: "ssh", target_node_id: target.id, os_user: osUser, reason: "remote access lab proof" },
  });
}

/** Opens the gateway WebSocket like the browser terminal does. */
function terminal(issued, { onConnected } = {}) {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(`${issued.gateway_url}/v1/session`);
    ws.binaryType = "arraybuffer";
    let output = "";
    const statuses = [];
    const started = Date.now();
    const timer = setTimeout(() => {
      ws.close();
      reject(new Error(`terminal timed out; statuses=${JSON.stringify(statuses)} output=${output}`));
    }, 90_000);
    ws.onopen = () => ws.send(JSON.stringify({ ticket: issued.ticket, cols: 100, rows: 30 }));
    ws.onmessage = (event) => {
      if (typeof event.data === "string") {
        const status = JSON.parse(event.data);
        statuses.push(status);
        if (status.state === "connected" && onConnected) onConnected(ws);
        return;
      }
      output += Buffer.from(event.data).toString("utf8");
    };
    ws.onerror = () => {};
    ws.onclose = () => {
      clearTimeout(timer);
      resolve({ output, statuses, closedAfterMs: Date.now() - started });
    };
  });
}

function closedReason(result) {
  return result.statuses.find((status) => status.state === "closed")?.reason ?? "none";
}

async function sessionId(orgId) {
  const issued = must(await issue(orgId), 201, "issue session");
  console.log(`ok ticket issued for session ${issued.session_id}, expires ${issued.ticket_expires_at}`);
  const result = await terminal(issued, {
    onConnected(ws) {
      ws.send(new TextEncoder().encode("id; exit\n"));
    },
  });
  const line = result.output.split(/\r?\n/).find((text) => text.includes("uid="));
  if (!line || !line.includes("(deploy)")) {
    throw new Error(`id output missing: ${JSON.stringify(result)}`);
  }
  console.log(`ok browser session ran id: ${line.trim()}`);
  console.log(`ok session closed: ${closedReason(result)}`);
  // The same ticket cannot be used twice.
  const again = await terminal(issued);
  const reason = closedReason(again);
  if (!reason.includes("already used")) throw new Error(`ticket reuse not refused: ${reason}`);
  console.log("ok reused ticket refused by the coordinator");
}

async function revokeLive(orgId) {
  const issued = must(await issue(orgId), 201, "issue session");
  let revokedAt = 0;
  const result = await terminal(issued, {
    onConnected() {
      revokedAt = Date.now();
      void api("POST", `/v1/orgs/${orgId}/remote-access/sessions/${issued.session_id}/revoke`, {
        orgId,
        sub: "lab-admin",
        role: "admin",
        body: {},
      });
    },
  });
  const reason = closedReason(result);
  const seconds = ((Date.now() - revokedAt) / 1000).toFixed(1);
  if (reason !== "revoked") throw new Error(`live session not ended by revoke: ${reason}`);
  console.log(`ok live session ended ${seconds}s after revoke (reason ${reason})`);
}

async function suspendLive(orgId) {
  const target = await nodeByName(orgId, "lab-target");
  const issued = must(await issue(orgId), 201, "issue session");
  let suspendedAt = 0;
  const result = await terminal(issued, {
    onConnected() {
      suspendedAt = Date.now();
      void api("POST", `/v1/orgs/${orgId}/nodes/${target.id}/suspend`, {
        orgId,
        sub: "lab-admin",
        role: "admin",
        body: { reason: "remote access lab" },
      });
    },
  });
  const reason = closedReason(result);
  const seconds = ((Date.now() - suspendedAt) / 1000).toFixed(1);
  if (!reason.includes("suspended")) throw new Error(`suspend did not end the session: ${reason}`);
  console.log(`ok live session ended ${seconds}s after the device was suspended (${reason})`);
  const refused = await issue(orgId);
  if (refused.status !== 409) throw new Error(`suspended device issued a ticket: ${refused.status}`);
  console.log(`ok suspended device refused: ${refused.body.error}`);
  must(
    await api("POST", `/v1/orgs/${orgId}/nodes/${target.id}/resume`, { orgId, sub: "lab-admin", role: "admin", body: {} }),
    204,
    "resume",
  );
}

async function forbidden(orgId) {
  const target = await nodeByName(orgId, "lab-target");
  const member = await api("POST", `/v1/orgs/${orgId}/remote-access/sessions`, {
    orgId,
    sub: "lab-member",
    role: "member",
    body: { kind: "ssh", target_node_id: target.id, os_user: "deploy", reason: "member attempt" },
  });
  if (member.status !== 403) throw new Error(`member got ${member.status}`);
  console.log("ok member refused (403)");
  const root = await issue(orgId, "root");
  if (root.status !== 409) throw new Error(`root not refused: ${root.status}`);
  console.log(`ok OS user outside the SSH rule refused: ${root.body.error}`);
}

async function expectMismatch(orgId) {
  const issued = must(await issue(orgId), 201, "issue session");
  const result = await terminal(issued);
  const reason = closedReason(result);
  if (reason !== "host_key_mismatch") throw new Error(`expected host_key_mismatch, got ${reason}`);
  if (result.output.length > 0) throw new Error("terminal bytes flowed despite a mismatch");
  const audit = must(await api("GET", `/v1/orgs/${orgId}/audit?limit=100`, { orgId }), 200, "audit");
  const events = Array.isArray(audit) ? audit : (audit.events ?? []);
  if (!events.some((event) => event.action === "remote_session.host_key_mismatch")) {
    throw new Error("host key mismatch not audited");
  }
  console.log("ok host key mismatch failed closed before login and was audited");
}

async function expectPending(orgId) {
  const deadline = Date.now() + 60_000;
  while (Date.now() < deadline) {
    const refused = await issue(orgId);
    if (refused.status === 409 && String(refused.body.error).includes("new SSH host key")) {
      console.log(`ok changed host key blocks new sessions: ${refused.body.error}`);
      return;
    }
    if (refused.status === 201) {
      // Not yet reported; let that ticket lapse.
      await sleep(61_000);
      continue;
    }
    await sleep(3000);
  }
  throw new Error("changed host key never blocked sessions");
}

async function jobs(orgId) {
  const target = await nodeByName(orgId, "lab-target");
  const make = async (name, argv, timeout) =>
    must(
      await api("POST", `/v1/orgs/${orgId}/remote-jobs/templates`, {
        orgId,
        body: { name, argv, timeout_secs: timeout, output_cap_bytes: 4096, target: { node_ids: [target.id] } },
      }),
      201,
      `template ${name}`,
    );
  const shell = await api("POST", `/v1/orgs/${orgId}/remote-jobs/templates`, {
    orgId,
    body: { name: "shell", argv: ["/bin/sh", "-c", "id"], timeout_secs: 5, output_cap_bytes: 64, target: { node_ids: [target.id] } },
  });
  if (shell.status !== 400) throw new Error(`shell template accepted: ${shell.status}`);
  console.log("ok shell template refused");
  const run = async (tpl) => {
    const requested = must(
      await api("POST", `/v1/orgs/${orgId}/remote-jobs/runs`, {
        orgId,
        sub: "lab-admin",
        role: "admin",
        body: { template_id: tpl.id, node_id: target.id, reason: "lab proof" },
      }),
      201,
      "request run",
    );
    must(
      await api("POST", `/v1/orgs/${orgId}/remote-jobs/runs/${requested.id}/approve`, { orgId, body: {} }),
      200,
      "approve",
    );
    return requested.id;
  };
  const waitFor = async (runId, states, timeoutMs = 90_000) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const runs = must(await api("GET", `/v1/orgs/${orgId}/remote-jobs/runs`, { orgId }), 200, "runs");
      const found = runs.find((row) => row.id === runId);
      if (found && states.includes(found.status)) return found;
      await sleep(2000);
    }
    throw new Error(`run ${runId} never reached ${states}`);
  };
  const id = await make("whoami", ["/usr/bin/id"], 30);
  const done = await waitFor(await run(id), ["succeeded", "failed", "error"]);
  if (done.status !== "succeeded" || !done.output.includes("(jobrunner)")) {
    throw new Error(`id job wrong: ${JSON.stringify(done)}`);
  }
  console.log(`ok approved job ran as the unprivileged user: ${done.output.trim()}`);
  const slow = await make("sleep", ["/usr/bin/sleep", "30"], 2);
  const timed = await waitFor(await run(slow), ["timed_out", "succeeded", "failed", "error"]);
  if (timed.status !== "timed_out") throw new Error(`timeout not enforced: ${timed.status}`);
  console.log(`ok job killed at its 2 s timeout (${timed.status})`);
  const long = await make("long sleep", ["/usr/bin/sleep", "120"], 300);
  const longRun = await run(long);
  await waitFor(longRun, ["running"]);
  must(
    await api("POST", `/v1/orgs/${orgId}/remote-jobs/runs/${longRun}/cancel`, { orgId, sub: "lab-admin", role: "admin", body: {} }),
    200,
    "cancel",
  );
  const cancelled = await waitFor(longRun, ["cancelled", "succeeded", "failed", "error"], 30_000);
  if (cancelled.status !== "cancelled") throw new Error(`cancel not enforced: ${cancelled.status}`);
  console.log("ok running job cancelled from the console");
  const verify = must(await api("GET", `/v1/orgs/${orgId}/audit/verify`, { orgId }), 200, "verify");
  if (!verify.intact) throw new Error(`audit chain broken: ${JSON.stringify(verify.problems)}`);
  console.log(`ok audit chain intact over ${verify.chained_events} events`);
}

const [command, orgId] = process.argv.slice(2);
const commands = {
  bootstrap,
  configure: () => configure(orgId),
  "wait-ready": () => waitReady(orgId),
  "session-id": () => sessionId(orgId),
  "revoke-live": () => revokeLive(orgId),
  "suspend-live": () => suspendLive(orgId),
  forbidden: () => forbidden(orgId),
  "expect-mismatch": () => expectMismatch(orgId),
  "expect-pending": () => expectPending(orgId),
  jobs: () => jobs(orgId),
};
if (!commands[command]) {
  console.error(`usage: remote-access-prove.mjs <${Object.keys(commands).join("|")}> [orgId]`);
  process.exit(2);
}
commands[command]().catch((error) => {
  console.error(`FAIL ${command}: ${error.message}`);
  process.exit(1);
});
