package au.org.blaktail

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns the Android TUN device. Plaintext packets go into the shared boringtun
 * engine. Ciphertext leaves on a protected UDP socket so the VPN does not
 * capture its own transport.
 */
class TunnelService : VpnService() {
    private val running = AtomicBoolean(false)
    private var tun: ParcelFileDescriptor? = null
    private var socket: DatagramSocket? = null
    private var tunnel: Long = 0
    private val workers = mutableListOf<Thread>()

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val address = intent?.getStringExtra(EXTRA_ADDRESS) ?: return START_NOT_STICKY
        val privateKey = intent.getByteArrayExtra(EXTRA_PRIVATE_KEY) ?: return START_NOT_STICKY
        val peers = intent.getStringArrayListExtra(EXTRA_PEERS) ?: arrayListOf()
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "BlakTail", NotificationManager.IMPORTANCE_LOW),
        )
        startForeground(
            1,
            Notification.Builder(this, CHANNEL)
                .setContentTitle("BlakTail")
                .setContentText(address)
                .setSmallIcon(android.R.drawable.stat_sys_download_done)
                .build(),
        )
        val prefix = address.substringAfter('/', "32").toIntOrNull() ?: 32
        val host = address.substringBefore('/')
        tun = Builder()
            .addAddress(host, prefix)
            .addRoute("100.64.0.0", 10)
            .setMtu(1280)
            .setSession("BlakTail")
            .establish()
        val fd = tun ?: return START_NOT_STICKY
        val tunnel = NativeTunnel.create(privateKey)
        if (tunnel == 0L) {
            stopSelf()
            return START_NOT_STICKY
        }
        for (peer in peers) {
            val parts = peer.split("|")
            if (parts.size < 2) continue
            val key = android.util.Base64.decode(parts[0], android.util.Base64.DEFAULT)
            NativeTunnel.addPeer(tunnel, key, parts[1].toByteArray())
        }
        val udp = DatagramSocket()
        protect(udp)
        udp.soTimeout = 50
        socket = udp
        this.tunnel = tunnel
        running.set(true)
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        workers += Thread {
            val buffer = ByteArray(2048)
            while (running.get()) {
                val count = runCatching { input.read(buffer) }.getOrDefault(-1)
                if (count <= 0) continue
                val framed = NativeTunnel.encapsulate(tunnel, buffer.copyOf(count)) ?: continue
                sendFramed(udp, peers, framed, null)
            }
        }.also(Thread::start)
        workers += Thread {
            val buffer = ByteArray(2048)
            val packet = DatagramPacket(buffer, buffer.size)
            var lastTick = 0L
            while (running.get()) {
                if (runCatching { udp.receive(packet) }.isSuccess) {
                    val reply = InetSocketAddress(packet.address, packet.port)
                    var framed = NativeTunnel.decapsulate(tunnel, packet.data.copyOf(packet.length))
                    while (framed != null) {
                        if (framed[0] == NativeTunnel.WRITE_TUNNEL) {
                            runCatching { output.write(framed, 33, framed.size - 33) }
                        } else {
                            sendFramed(udp, peers, framed, reply)
                        }
                        framed = NativeTunnel.decapsulate(tunnel, ByteArray(0))
                    }
                }
                val now = System.currentTimeMillis()
                if (now - lastTick > 250) {
                    lastTick = now
                    var framed = NativeTunnel.tick(tunnel)
                    while (framed != null) {
                        sendFramed(udp, peers, framed, null)
                        framed = NativeTunnel.tick(tunnel)
                    }
                }
            }
        }.also(Thread::start)
        return START_STICKY
    }

    override fun onDestroy() {
        running.set(false)
        socket?.close()
        tun?.close()
        workers.forEach { it.join(500) }
        if (tunnel != 0L) {
            NativeTunnel.free(tunnel)
            tunnel = 0
        }
        super.onDestroy()
    }

    private fun sendFramed(
        udp: DatagramSocket,
        peers: List<String>,
        framed: ByteArray,
        reply: InetSocketAddress?,
    ) {
        if (framed.size < 33 || framed[0] != NativeTunnel.WRITE_NETWORK) return
        val endpoint = reply ?: endpointFor(peers, framed.copyOfRange(1, 33)) ?: return
        val payload = framed.copyOfRange(33, framed.size)
        runCatching { udp.send(DatagramPacket(payload, payload.size, endpoint)) }
    }

    private fun endpointFor(peers: List<String>, publicKey: ByteArray): InetSocketAddress? {
        val encoded = android.util.Base64.encodeToString(publicKey, android.util.Base64.NO_WRAP)
        val match = peers.firstOrNull { it.substringBefore("|") == encoded } ?: return null
        val endpoint = match.split("|").getOrNull(2)?.takeIf { it.isNotBlank() } ?: return null
        val port = endpoint.substringAfterLast(':').toIntOrNull() ?: return null
        var host = endpoint.substringBeforeLast(':')
        if (host.startsWith('[') && host.endsWith(']')) host = host.substring(1, host.length - 1)
        return InetSocketAddress(host, port)
    }

    companion object {
        const val EXTRA_ADDRESS = "address"
        const val EXTRA_PRIVATE_KEY = "privateKey"
        const val EXTRA_PEERS = "peers"
        private const val CHANNEL = "blaktail"
    }
}
