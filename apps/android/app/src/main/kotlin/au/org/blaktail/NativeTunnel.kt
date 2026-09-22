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

    const val WRITE_NETWORK: Byte = 1
    const val WRITE_TUNNEL: Byte = 2
}
