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
 * "direct", "udp_relay" or "https_relay". If dst_cap is too small, sets
 * dst_len to the size needed, keeps the counters and returns -1. */
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

#ifdef __cplusplus
}
#endif

#endif
