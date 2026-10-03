package au.org.blaktail

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import org.json.JSONObject
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean

/**
 * Owns the Android TUN device. Plaintext packets go into the shared boringtun
 * engine. Ciphertext leaves on protected UDP sockets so the VPN does not
 * capture its own transport: one for direct peer paths and one for the
 * Australian relay fallback, whose decisions (relay choice, failover,
 * direct/relay hysteresis) are made by the shared Rust core.
 */
class TunnelService : VpnService() {
    private val running = AtomicBoolean(false)
    private var tun: ParcelFileDescriptor? = null
    private var socket: DatagramSocket? = null
    private var relaySocket: DatagramSocket? = null
    private var tunnel: Long = 0
    private val workers = mutableListOf<Thread>()
    private val relayAddresses = ConcurrentHashMap<String, InetSocketAddress>()

    @Volatile
    private var activeRelay: String? = null

    @Volatile
    private var transport = "none"

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val address = intent?.getStringExtra(EXTRA_ADDRESS) ?: return START_NOT_STICKY
        val privateKey = intent.getByteArrayExtra(EXTRA_PRIVATE_KEY) ?: return START_NOT_STICKY
        val peers = intent.getStringArrayListExtra(EXTRA_PEERS) ?: arrayListOf()
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "BlakTail", NotificationManager.IMPORTANCE_LOW),
        )
        startForeground(1, notification(address))
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
        // Inbound filter between decrypt and the TUN write. A phone enrolled
        // before policies were stored has none, which leaves it unfiltered.
        intent.getStringExtra(EXTRA_POLICY)?.let { NativeTunnel.setPolicy(tunnel, it.toByteArray()) }
        val udp = DatagramSocket()
        protect(udp)
        udp.soTimeout = 50
        socket = udp
        val relayUdp = DatagramSocket()
        protect(relayUdp)
        relayUdp.soTimeout = 200
        relaySocket = relayUdp
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
                    if (framed != null && framed.size >= 33) {
                        // Decrypted on the direct socket: proof the direct path works.
                        NativeTunnel.relayDirectReceived(tunnel, framed.copyOfRange(1, 33))
                    }
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
        workers += Thread { relayLoop(tunnel, relayUdp, udp, output, peers, address) }.also(Thread::start)
        BlakTailWidget.publish(this, true)
        return START_STICKY
    }

    /**
     * Refreshes the relay capability from the coordinator, carries relay
     * frames, and runs the core's once-a-second relay timers.
     */
    private fun relayLoop(
        tunnel: Long,
        relayUdp: DatagramSocket,
        udp: DatagramSocket,
        output: FileOutputStream,
        peers: List<String>,
        address: String,
    ) {
        val buffer = ByteArray(4096)
        val packet = DatagramPacket(buffer, buffer.size)
        var lastRefresh = 0L
        var lastTick = 0L
        while (running.get()) {
            val now = System.currentTimeMillis()
            if (now - lastRefresh > REFRESH_MILLIS) {
                lastRefresh = now
                refreshRelay(tunnel, peers)
            }
            if (runCatching { relayUdp.receive(packet) }.isSuccess) {
                val source = InetSocketAddress(packet.address, packet.port)
                val endpoint = relayAddresses.entries.firstOrNull { it.value == source }?.key
                if (endpoint != null) {
                    val unwrapped = NativeTunnel.relayInbound(tunnel, packet.data.copyOf(packet.length), endpoint)
                    if (unwrapped != null && unwrapped.size > 32) {
                        var framed = NativeTunnel.decapsulate(tunnel, unwrapped.copyOfRange(32, unwrapped.size))
                        while (framed != null) {
                            if (framed[0] == NativeTunnel.WRITE_TUNNEL) {
                                runCatching { output.write(framed, 33, framed.size - 33) }
                            } else {
                                sendFramed(udp, peers, framed, null)
                            }
                            framed = NativeTunnel.decapsulate(tunnel, ByteArray(0))
                        }
                    }
                }
            }
            if (now - lastTick >= 1_000) {
                lastTick = now
                NativeTunnel.relayTick(tunnel)
                var control = NativeTunnel.relayPoll(tunnel)
                while (control != null) {
                    sendControl(relayUdp, control)
                    control = NativeTunnel.relayPoll(tunnel)
                }
                updateStatus(tunnel, address)
            }
        }
    }

    private fun refreshRelay(tunnel: Long, peers: List<String>) {
        val prefs = getSharedPreferences("blaktail", MODE_PRIVATE)
        val coordinator = prefs.getString("coordinator", null) ?: return
        val nodeId = prefs.getString("nodeId", null) ?: return
        val nodeToken = prefs.getString("nodeToken", null) ?: return
        val map = runCatching { EnrolmentClient(coordinator).peers(nodeId, nodeToken) }.getOrNull() ?: return
        // The same response carries the current inbound grants.
        NativeTunnel.setPolicy(tunnel, map.policy.toByteArray())
        prefs.edit().putString("policy", map.policy).apply()
        val settings = map.relay
        NativeTunnel.relayConfigure(tunnel, nodeId, settings.token, settings.expiresAt, settings.relays)
        NativeTunnel.relayBeginPeers(tunnel)
        for (peer in peers) {
            val parts = peer.split("|")
            val id = parts.getOrNull(3)?.takeIf { it.isNotBlank() } ?: continue
            val key = android.util.Base64.decode(parts[0], android.util.Base64.DEFAULT)
            NativeTunnel.relaySetPeer(tunnel, key, id, parts.getOrNull(2)?.isNotBlank() == true)
        }
        NativeTunnel.relayEndPeers(tunnel)
    }

    private fun sendControl(relayUdp: DatagramSocket, control: ByteArray) {
        if (control.size < 3 || control[0].toInt() != NativeTunnel.ROUTE_UDP) return
        val length = ((control[1].toInt() and 0xff) shl 8) or (control[2].toInt() and 0xff)
        if (control.size < 3 + length) return
        val endpoint = String(control, 3, length, Charsets.UTF_8)
        val target = relayAddress(endpoint) ?: return
        val frame = control.copyOfRange(3 + length, control.size)
        runCatching { relayUdp.send(DatagramPacket(frame, frame.size, target)) }
    }

    private fun relayAddress(endpoint: String): InetSocketAddress? {
        relayAddresses[endpoint]?.let { return it }
        val parsed = parseEndpoint(endpoint) ?: return null
        if (parsed.isUnresolved) return null
        relayAddresses[endpoint] = parsed
        return parsed
    }

    private fun updateStatus(tunnel: Long, address: String) {
        val json = NativeTunnel.relayStatus(tunnel) ?: return
        val status = runCatching { JSONObject(json) }.getOrNull() ?: return
        activeRelay = if (status.isNull("relay")) null else status.optString("relay")
        val next = status.optString("transport", "none")
        if (next != transport) {
            transport = next
            getSystemService(NotificationManager::class.java).notify(1, notification(address))
        }
    }

    private fun notification(address: String): Notification {
        val path = when (transport) {
            "direct" -> "direct"
            "relay" -> "via Australian relay"
            "relay-wss" -> "via Australian relay (HTTPS)"
            else -> "waiting for traffic"
        }
        return Notification.Builder(this, CHANNEL)
            .setContentTitle("BlakTail")
            .setContentText("$address · $path")
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .build()
    }

    override fun onDestroy() {
        running.set(false)
        BlakTailWidget.publish(this, false)
        socket?.close()
        relaySocket?.close()
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
        val key = framed.copyOfRange(1, 33)
        val payload = framed.copyOfRange(33, framed.size)
        val routed = NativeTunnel.relayOutbound(tunnel, key, payload)
        val flags = routed?.firstOrNull()?.toInt() ?: NativeTunnel.ROUTE_DIRECT
        if (flags and NativeTunnel.ROUTE_DIRECT != 0) {
            val endpoint = reply ?: endpointFor(peers, key)
            if (endpoint != null) {
                runCatching { udp.send(DatagramPacket(payload, payload.size, endpoint)) }
            }
        }
        if (flags and NativeTunnel.ROUTE_UDP != 0 && routed != null && routed.size > 1) {
            val relay = activeRelay?.let(::relayAddress) ?: return
            val frame = routed.copyOfRange(1, routed.size)
            runCatching { relaySocket?.send(DatagramPacket(frame, frame.size, relay)) }
        }
    }

    private fun endpointFor(peers: List<String>, publicKey: ByteArray): InetSocketAddress? {
        val encoded = android.util.Base64.encodeToString(publicKey, android.util.Base64.NO_WRAP)
        val match = peers.firstOrNull { it.substringBefore("|") == encoded } ?: return null
        val endpoint = match.split("|").getOrNull(2)?.takeIf { it.isNotBlank() } ?: return null
        return parseEndpoint(endpoint)
    }

    private fun parseEndpoint(endpoint: String): InetSocketAddress? {
        val port = endpoint.substringAfterLast(':').toIntOrNull() ?: return null
        var host = endpoint.substringBeforeLast(':')
        if (host.startsWith('[') && host.endsWith(']')) host = host.substring(1, host.length - 1)
        return runCatching { InetSocketAddress(host, port) }.getOrNull()
    }

    companion object {
        const val EXTRA_ADDRESS = "address"
        const val EXTRA_PRIVATE_KEY = "privateKey"
        const val EXTRA_PEERS = "peers"
        const val EXTRA_POLICY = "policy"
        private const val CHANNEL = "blaktail"
        private const val REFRESH_MILLIS = 5 * 60 * 1000L
    }
}
