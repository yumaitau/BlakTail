#ifndef BLAKTAIL_IOS_WG_H
#define BLAKTAIL_IOS_WG_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct BlakTailTunnel BlakTailTunnel;

enum {
    BLAKTAIL_WG_DONE = 0,
    BLAKTAIL_WG_WRITE_NETWORK = 1,
    BLAKTAIL_WG_WRITE_TUNNEL = 2,
    BLAKTAIL_WG_ERR = -1
};

BlakTailTunnel *blaktail_tunnel_create(const uint8_t private_key[32]);
void blaktail_tunnel_free(BlakTailTunnel *tunnel);
void blaktail_tunnel_clear_peers(BlakTailTunnel *tunnel);

int blaktail_tunnel_add_peer(
    BlakTailTunnel *tunnel,
    const uint8_t public_key[32],
    const char *allowed_ips,
    uint16_t keepalive_seconds
);

int blaktail_tunnel_encapsulate(
    BlakTailTunnel *tunnel,
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t dst_cap,
    size_t *dst_len,
    uint8_t peer_public_out[32]
);

int blaktail_tunnel_decapsulate(
    BlakTailTunnel *tunnel,
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t dst_cap,
    size_t *dst_len,
    uint8_t peer_public_out[32]
);

int blaktail_tunnel_update_timers(
    BlakTailTunnel *tunnel,
    uint8_t *dst,
    size_t dst_cap,
    size_t *dst_len,
    uint8_t peer_public_out[32]
);

/* Inbound policy from the coordinator's `peers` JSON array (`id`,
 * `allowed_ips`, `ingress`). Invalid JSON installs deny-all and returns -1. */
int blaktail_tunnel_set_policy(BlakTailTunnel *tunnel, const uint8_t *json, size_t len);

/* Traffic counters on (non-zero) or off; off discards them at once. */
int blaktail_tunnel_set_traffic(BlakTailTunnel *tunnel, int enabled);

/* Writes the coordinator traffic upload body ({"records":[...]}) for the
 * counters since the last successful call and resets them. transport is
 * "direct", "udp_relay" or "https_relay"; once the relay is configured its
 * state decides instead. If dst_cap is too small, sets dst_len to the size
 * needed, keeps the counters and returns -1. */
int blaktail_tunnel_take_flow_upload(
    BlakTailTunnel *tunnel,
    const char *org_id,
    const char *device_id,
    const char *transport,
    double sampling_rate,
    uint8_t *dst,
    size_t dst_cap,
    size_t *dst_len
);

/*
 * Relay fallback (Australian BlakTail relay over UDP, or the WSS fallback).
 * The platform owns the sockets; these calls decide what goes where.
 */
enum {
    BLAKTAIL_RELAY_ROUTE_DIRECT = 1,
    BLAKTAIL_RELAY_ROUTE_UDP = 2,
    BLAKTAIL_RELAY_ROUTE_WSS = 4
};

/* `relays`: one relay per line, "endpoint\tregion\twss_url" (wss may be
 * empty). Offshore relays are ignored. A token that is not 64 hex chars
 * leaves the relay off. */
int blaktail_relay_configure(
    BlakTailTunnel *tunnel,
    const char *self_node_id,
    const char *relay_token_hex,
    uint64_t relay_expires_at_unix,
    const char *relays,
    uint8_t allow_wss
);

void blaktail_relay_begin_peers(BlakTailTunnel *tunnel);
int blaktail_relay_set_peer(
    BlakTailTunnel *tunnel,
    const uint8_t public_key[32],
    const char *node_id,
    uint8_t has_direct_endpoint
);
void blaktail_relay_end_peers(BlakTailTunnel *tunnel);

/* Returns BLAKTAIL_RELAY_ROUTE_* flags. DIRECT: send `src` to the peer's
 * endpoint. UDP/WSS: send dst[0..*dst_len] to the relay. */
int blaktail_relay_outbound(
    BlakTailTunnel *tunnel,
    const uint8_t peer_public[32],
    const uint8_t *src,
    size_t src_len,
    uint8_t *dst,
    size_t dst_cap,
    size_t *dst_len
);

/* Returns 1 with WireGuard ciphertext in dst (pass it to
 * blaktail_tunnel_decapsulate, which applies the inbound policy exactly as
 * for direct traffic), 0 when consumed or refused, -1 on error. */
int blaktail_relay_inbound(
    BlakTailTunnel *tunnel,
    const uint8_t *src,
    size_t src_len,
    uint8_t via_wss,
    const char *udp_endpoint,
    uint8_t *dst,
    size_t dst_cap,
    size_t *dst_len,
    uint8_t peer_public_out[32]
);

void blaktail_relay_direct_received(BlakTailTunnel *tunnel, const uint8_t peer_public[32]);
void blaktail_relay_tick(BlakTailTunnel *tunnel);

/* Returns 0 (nothing), BLAKTAIL_RELAY_ROUTE_UDP (send to endpoint_out) or
 * BLAKTAIL_RELAY_ROUTE_WSS. */
int blaktail_relay_poll(
    BlakTailTunnel *tunnel,
    uint8_t *dst,
    size_t dst_cap,
    size_t *dst_len,
    char *endpoint_out,
    size_t endpoint_cap
);

/* NUL-terminated JSON: transport, relay, link, wss_url, healthy,
 * peers_direct, peers_relayed, failovers. Returns length or -1. */
long blaktail_relay_status(BlakTailTunnel *tunnel, char *out, size_t cap);

#ifdef __cplusplus
}
#endif

#endif
