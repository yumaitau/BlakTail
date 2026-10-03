package au.org.blaktail

object NativeTunnel {
    init {
        System.loadLibrary("blaktail_ios_wg")
    }

    external fun publicKey(privateKey: ByteArray): ByteArray
    external fun create(privateKey: ByteArray): Long
    external fun free(tunnel: Long)
    external fun addPeer(tunnel: Long, publicKey: ByteArray, allowedIps: ByteArray): Int
    external fun encapsulate(tunnel: Long, packet: ByteArray): ByteArray?
    external fun decapsulate(tunnel: Long, packet: ByteArray): ByteArray?
    external fun tick(tunnel: Long): ByteArray?

    // Australian relay fallback (UDP only on Android; see docs/android.md).
    // `relays` is one relay per line: "endpoint\tregion\twss".
    external fun relayConfigure(tunnel: Long, selfId: String, tokenHex: String, expiresAt: Long, relays: String): Int
    external fun relayBeginPeers(tunnel: Long)
    external fun relaySetPeer(tunnel: Long, publicKey: ByteArray, nodeId: String, hasDirect: Boolean): Int
    external fun relayEndPeers(tunnel: Long)

    /** `[flags][SEND frame]`; flags use the ROUTE_* bits. */
    external fun relayOutbound(tunnel: Long, publicKey: ByteArray, datagram: ByteArray): ByteArray?

    /** `[peer public key (32)][WireGuard ciphertext]`, or null for control replies. */
    external fun relayInbound(tunnel: Long, frame: ByteArray, endpoint: String): ByteArray?
    external fun relayDirectReceived(tunnel: Long, publicKey: ByteArray)
    external fun relayTick(tunnel: Long)

    /** `[kind][u16 endpoint length][endpoint][frame]`, or null when nothing is due. */
    external fun relayPoll(tunnel: Long): ByteArray?
    external fun relayStatus(tunnel: Long): String?

    const val WRITE_NETWORK: Byte = 1
    const val WRITE_TUNNEL: Byte = 2
    const val ROUTE_DIRECT = 1
    const val ROUTE_UDP = 2
    const val ROUTE_WSS = 4
}
