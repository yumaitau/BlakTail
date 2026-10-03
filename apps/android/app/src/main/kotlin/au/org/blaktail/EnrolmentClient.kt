package au.org.blaktail

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.security.SecureRandom
import java.util.Base64

data class EnrolmentStart(
    val deviceCode: String,
    val userCode: String,
    val verificationUrl: String,
)

data class Joined(
    val id: String,
    val nodeToken: String,
    val address: String,
)

/** Relay capability and Australian relays from the coordinator's peer map. */
data class RelaySettings(
    val token: String,
    val expiresAt: Long,
    /** One relay per line: "endpoint\tregion\twss" (wss may be empty). */
    val relays: String,
)

class EnrolmentClient(private val coordinatorUrl: String) {
    fun start(name: String, publicKey: String): EnrolmentStart {
        val body = """{"name":${json(name)},"wg_public_key":${json(publicKey)}}"""
        val response = request("POST", "/v1/device-authorizations", body)
        return EnrolmentStart(
            deviceCode = field(response, "device_code"),
            userCode = field(response, "user_code"),
            verificationUrl = field(response, "verification_url"),
        )
    }

    fun approved(deviceCode: String): Boolean {
        val connection = open("GET", "/v1/device-authorizations/$deviceCode")
        return connection.responseCode == 200
    }

    fun awaitApproved(deviceCode: String) {
        val deadline = System.currentTimeMillis() + 10 * 60 * 1000
        while (System.currentTimeMillis() < deadline) {
            if (approved(deviceCode)) return
            Thread.sleep(2_000)
        }
        error("Enrolment was not approved")
    }

    fun register(deviceCode: String, name: String, publicKey: String): Joined {
        val body =
            """{"join_key":${json(deviceCode)},"name":${json(name)},"wg_public_key":${json(publicKey)},"os":"android"}"""
        val parsed = JSONObject(request("POST", "/v1/nodes/register", body))
        val addresses = parsed.optJSONArray("assigned_ips")
        val address = when {
            addresses != null && addresses.length() > 0 -> addresses.getString(0)
            else -> parsed.getString("assigned_ip")
        }
        val cidr = if (address.contains('/')) address else "$address/32"
        return Joined(parsed.getString("id"), parsed.getString("node_token"), cidr)
    }

    /** Peers as "key|cidrs|endpoint|nodeId". */
    fun peers(nodeId: String, nodeToken: String): ArrayList<String> = peerMap(nodeId, nodeToken).first

    fun relaySettings(nodeId: String, nodeToken: String): RelaySettings = peerMap(nodeId, nodeToken).second

    private fun peerMap(nodeId: String, nodeToken: String): Pair<ArrayList<String>, RelaySettings> {
        val connection = open("GET", "/v1/nodes/$nodeId/peers")
        connection.setRequestProperty("authorization", "Bearer $nodeToken")
        val stream = if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream
        val text = stream.bufferedReader().readText()
        if (connection.responseCode !in 200..299) error("coordinator returned ${connection.responseCode}")
        val body = JSONObject(text)
        val list = body.getJSONArray("peers")
        val peers = ArrayList<String>()
        for (index in 0 until list.length()) {
            val peer = list.getJSONObject(index)
            val allowed = peer.getJSONArray("allowed_ips")
            if (allowed.length() == 0) continue
            val cidrs = (0 until allowed.length()).joinToString(",") { allowed.getString(it) }
            val endpoint = if (peer.isNull("endpoint")) "" else peer.optString("endpoint")
            peers.add("${peer.getString("wg_public_key")}|$cidrs|$endpoint|${peer.optString("id")}")
        }
        val declared = body.optJSONArray("relay_endpoints")
        val relays = if (declared != null && declared.length() > 0) {
            (0 until declared.length()).joinToString("\n") {
                val relay = declared.getJSONObject(it)
                val wss = if (relay.isNull("wss")) "" else relay.optString("wss")
                "${relay.getString("endpoint")}\t${relay.getString("region")}\t$wss"
            }
        } else {
            // Older coordinators list relays without regions; they validated
            // their own Australian region, as the desktop agent assumes too.
            val legacy = body.optJSONArray("relays")
            (0 until (legacy?.length() ?: 0)).joinToString("\n") { "${legacy!!.getString(it)}\tap-southeast-2\t" }
        }
        return peers to RelaySettings(body.optString("relay_token"), body.optLong("relay_expires_at"), relays)
    }

    fun newPublicKey(): String = Base64.getEncoder().encodeToString(ByteArray(32).also(SecureRandom()::nextBytes))

    private fun request(method: String, path: String, body: String?): String {
        val connection = open(method, path)
        if (body != null) {
            connection.doOutput = true
            connection.outputStream.use { it.write(body.toByteArray()) }
        }
        val stream = if (connection.responseCode in 200..299) connection.inputStream else connection.errorStream
        val text = stream.bufferedReader().readText()
        if (connection.responseCode !in 200..299) {
            error("coordinator returned ${connection.responseCode}")
        }
        return text
    }

    private fun open(method: String, path: String): HttpURLConnection {
        val connection = URI.create(coordinatorUrl.trimEnd('/') + path).toURL().openConnection() as HttpURLConnection
        connection.requestMethod = method
        connection.setRequestProperty("content-type", "application/json")
        connection.connectTimeout = 15_000
        connection.readTimeout = 15_000
        return connection
    }

    private fun json(value: String): String = "\"" + value.replace("\\", "\\\\").replace("\"", "\\\"") + "\""

    private fun field(json: String, name: String): String {
        val marker = "\"$name\":\""
        val start = json.indexOf(marker)
        if (start < 0) error("coordinator response has no $name")
        val from = start + marker.length
        val end = json.indexOf('"', from)
        return json.substring(from, end)
    }
}
