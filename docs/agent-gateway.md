# Agent network (AI model gateway)

The agent network lets an organisation run its own AI model gateway on one of
its BlakTail devices. Agents (scripts, bots, desktop tools) call an
OpenAI-compatible API on that device over the BlakTail overlay with a
per-agent key. The coordinator decides every request; the gateway forwards it
to a model provider the organisation configured and reports token usage back.

Decision record: [ADR 0008](adr/0008-agent-network.md). Its sovereignty and
ICIP conditions are requirements, summarised under [Guarantees and limits](#guarantees-and-limits).

## Pieces

| Piece | Where | What it does |
| --- | --- | --- |
| `blaktail-agentgw` | an enrolled node | `GET /v1/models`, `POST /v1/chat/completions` (JSON and SSE streaming), `GET /healthz`. Listens only on the node's overlay address. |
| Coordinator | `blaktail-coord/src/agent_gateway.rs` | Providers, agent keys, policies, quotas, usage and audit. Authorises each request for the gateway node. |
| Console | `/agents` (nav group **Agents**) | Offshore policy, providers with location, keys and policies, usage table and chart, stored-prompt viewer for owners. |

## Set up

1. Enrol (or re-run `up` on) the gateway device with the opt-in flag, so it
   reports the `agent-gateway` capability:

   ```sh
   blaktaild up --coord https://coord.example.org.au --agent-gateway
   ```

2. Start the gateway on that device. It reads the node id, node token and
   coordinator from blaktaild's state file and binds the overlay address on
   port 8686:

   ```sh
   blaktail-agentgw --state-file /var/lib/blaktail/state.json --coord-ca /etc/blaktail/coord-ca.pem
   ```

   It refuses `0.0.0.0`, `::` and any address that is not loopback or
   BlakTail overlay (`100.64.0.0/10`, `fd7a:115c:a1e0::/48`). RFC 1918 / ULA
   addresses need `--allow-private-listen` and are meant for labs only.

3. In the console, open **Agents → Agent network**:
   - Add a provider: name, OpenAI-compatible base URL (for Ollama,
     `http://<host>:11434/v1`), the models it serves, a **data location**
     (free text, e.g. "Australia (self-hosted, Mparntwe office)") and an
     explicit **onshore/offshore** residency. An optional credential is sealed
     and never shown again.
   - Create an agent key and its policy. Copy the key; it is shown once.

4. Allow the agent's devices to reach the gateway device with ordinary
   [access policy](policy.md). Network policy decides who can reach the
   gateway; the key's policy decides what the agent may do there.

5. Point the agent at `http://<gateway overlay address or MagicDNS name>:8686/v1`
   with `Authorization: Bearer btak_…`.

## Policy per agent key

| Setting | Default | Notes |
| --- | --- | --- |
| Allowed providers | none | A key with no providers can do nothing. |
| Allowed models | all models the allowed providers declare | Exact model ids. |
| Requests per day | 1000 | UTC day. Checked atomically before forwarding; concurrent requests never exceed it. |
| Tokens per day | 1,000,000 | Checked before forwarding; a single request can overshoot by its own size. |
| Max request size | 256 KiB | Hard ceiling 4 MiB at the gateway. |
| Bound device | none | When set, the key works only from that device's overlay address (the gateway reports the caller's source address and the coordinator maps it to a device). |
| Redaction patterns | none | Up to 16 regular expressions; matches in message text become `[REDACTED]` before the provider sees them. If a pattern cannot compile the request is refused. |
| Prompt logging | off | See below. |

### Prompt logging

- **Off** (default): only daily totals per key and model (requests, errors,
  prompt/completion tokens). No per-request record.
- **Metadata only**: adds a per-request record (time, model, provider,
  calling device, status, latency, token counts) kept for 90 days.
- **Full**: also stores the (already redacted) request body and the response
  text, sealed with the coordinator secret. Only an **owner** can turn it on,
  must acknowledge the Indigenous Cultural and Intellectual Property warning,
  and must set retention to 1–30 days. Content is purged at expiry, and
  immediately when the key leaves full logging or is revoked. Only owners can
  read stored prompts, and every read is audited
  (`agent.request_content.viewed`).

## Offshore providers

Every provider must be declared `onshore` or `offshore`; there is no default.
Organisations forbid offshore providers by default: the gateway refuses a
request whose only matching provider is offshore (`403 offshore_forbidden`),
and `/v1/models` omits offshore models. Only an owner can allow offshore
providers. Offshore providers must use HTTPS. Residency and location are
*declared* by administrators; BlakTail cannot verify where a third party
processes data and the console says so.

## Permissions

| Permission | Roles | Covers |
| --- | --- | --- |
| `manage_agent_gateway` | owner, admin | Providers, keys, policies. Owner-only within it: the offshore policy, turning on full logging, reading stored prompts. |
| `view_agent_usage` | owner, admin, auditor | Configuration (never credentials), usage and per-request metadata. |

Members and network admins have neither. Every mutation is audited
(`agent.settings.updated`, `agent.provider.created|updated|deleted`,
`agent.key.created|policy_updated|revoked`). Audit details never contain a
credential or key, only `has_credential` / `credential_replaced` flags and the
key prefix.

## Coordinator API

Console routes (console assertion, organisation-scoped):

| Method and path | Permission |
| --- | --- |
| `GET /v1/orgs/:org/agents` | `view_agent_usage` |
| `PUT /v1/orgs/:org/agents/settings` | `manage_agent_gateway`, owner |
| `POST /v1/orgs/:org/agents/providers` | `manage_agent_gateway` |
| `PATCH`/`DELETE /v1/orgs/:org/agents/providers/:id` | `manage_agent_gateway` (PATCH needs `revision`; stale is 412) |
| `POST /v1/orgs/:org/agents/keys` | `manage_agent_gateway` (returns the secret once) |
| `PUT`/`DELETE /v1/orgs/:org/agents/keys/:id` | `manage_agent_gateway` (PUT needs `revision`) |
| `GET /v1/orgs/:org/agents/usage?days=14` | `view_agent_usage` |
| `GET /v1/orgs/:org/agents/requests/:id/content` | owner |

Gateway routes (node bearer token; node must be active, not suspended or
expired, and report the `agent-gateway` capability):

| Method and path | Purpose |
| --- | --- |
| `POST /v1/nodes/:node/agent-gateway/authorize` | Key, binding, size, allowlist, offshore and quota decision; reserves one request and returns the upstream grant. |
| `POST /v1/nodes/:node/agent-gateway/models` | Models a key may use now. |
| `POST /v1/nodes/:node/agent-gateway/usage` | Closes a reservation once, from the gateway that opened it, with token counts. |

No `/api/v1` automation endpoints exist for the agent network yet.

## Guarantees and limits

- **Never public.** Bind checks above; reachability is BlakTail policy.
- **Secrets.** Provider credentials are sealed at rest (same helper as the
  private-service CA key), never returned after creation and never logged.
  They leave the coordinator only inside a grant to an authenticated gateway
  node, which holds them in memory for one request. Agent keys are stored as
  SHA-256 hashes. The gateway wraps keys, node token and credentials in a type
  whose debug output is `[redacted]`, and tests capture all logs and assert
  none of them appear.
- **Fail closed.** No coordinator, no request (`503 gateway_unavailable`).
- **Redirects are not followed** to upstreams, so a provider cannot bounce a
  credential-bearing request elsewhere. Provider URLs cannot carry userinfo,
  query strings, link-local or cloud-metadata hosts; a credential may only go
  over plain HTTP to a private or loopback address.
- **Token counts** come from the provider's `usage` object. For streams the
  gateway asks for `stream_options.include_usage`; if none arrives it estimates
  (characters / 4) and marks the record *estimated*.
- **Not built:** Anthropic Messages API translation (use an
  OpenAI-compatible endpoint), embeddings and other OpenAI endpoints, tool or
  MCP allowlists, per-model pricing or billing, and re-sealing after a
  coordinator secret rotation. DNS rebinding of a provider hostname to a
  metadata address is not re-checked at connect time.

## Tests

- `cargo test -p blaktail-coord agent_gateway` — key auth and revocation,
  daily request and token quotas, 20 concurrent requests against a quota of 5
  (exactly 5 allowed), offshore forbidden by default and owner-only override,
  model allowlist and request size, node binding by overlay address,
  credential never returned/stored in clear/audited, full-logging owner + ICIP
  acknowledgement + ≤30 days, content sealed and purged on mode change,
  usage recorded once by the reserving gateway, cross-organisation isolation,
  member/network-admin/auditor rejection, provider URL validation.
- `cargo test -p blaktail-agentgw` — a real in-memory coordinator, the gateway
  and a local axum mock upstream: non-streaming and byte-for-byte SSE
  passthrough with usage metered, redaction before forwarding, bad key and
  exhausted quota never reach the upstream, `/v1/models`, and a captured log
  stream that contains no key, node token or credential.

## Live lab

`deploy/homelab/prove-agent-gateway.sh` (run with `DOCKER_CONTEXT` set to a lab
Docker host) builds Linux release binaries and starts, on a private Docker
network: a TLS coordinator, the gateway, and a real Ollama serving
`qwen2.5:0.5b`. It enrols the gateway node with the `agent-gateway`
capability, configures an onshore Ollama provider and an offshore provider,
mints a key (quota 3/day, metadata logging, a redaction pattern) and drives
requests through the gateway.

Result on the `m3-max` lab host (16 CPU, OrbStack, Linux arm64), 3 October 2026:

```
ok gateway node enrolled with capability agent-gateway at 100.64.0.1/32
ok providers: lab-ollama "Australia (self-hosted lab)" onshore, blocked_by_policy false;
   hosted-offshore "United States (hosted)" offshore, blocked_by_policy true, has_credential true
ok agent key btak_-AfktO5… (secret shown once, stored only as a hash)
ok refused: "refusing to listen on every interface; bind the node's overlay address"
ok /v1/models: [{"id":"qwen2.5:0.5b","residency":"onshore","data_location":"Australia (self-hosted lab)"}]
ok non-streaming completion via gateway (200)   reply "Hello!", usage 45 + 3
ok streaming completion via gateway (200)       12 SSE chunks, ends with [DONE], usage chunk 45 + 10
ok offshore provider refused by default (403 offshore_forbidden)
ok unknown agent key refused (401)
ok third request inside quota (200)
ok fourth request over the daily quota of 3 (429)
ok quota counters for lab-agent today: {"requests":3,"tokens":158,"denied":2}
ok usage by day/model: 2026-10-03 lab-agent qwen2.5:0.5b requests 3, prompt 135, completion 23
ok recent requests: 3 x status ok, usage_estimated false
ok audit: ["agent.key.created","agent.provider.created"]
ok gateway log (7 lines) holds no agent key, node token or provider credential
```

The first run failed before any request because the coordinator needs
`BLAKTAIL_CONSOLE_URL`; the script now sets it. Limits of this proof: the
gateway bound its Docker-network address with `--allow-private-listen`
instead of a WireGuard overlay address, the caller was not an enrolled device
(so node binding was not exercised live; it is covered by coordinator tests),
and Ollama ran on CPU.
