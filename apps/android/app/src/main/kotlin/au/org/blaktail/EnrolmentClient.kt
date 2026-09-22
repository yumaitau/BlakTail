package au.org.blaktail

import java.net.HttpURLConnection
import java.net.URI
import java.security.SecureRandom
import java.util.Base64

data class EnrolmentStart(
    val deviceCode: String,
    val userCode: String,
    val verificationUrl: String,
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

    fun register(deviceCode: String, name: String, publicKey: String): String {
        val body =
            """{"join_key":${json(deviceCode)},"name":${json(name)},"wg_public_key":${json(publicKey)},"os":"android"}"""
        return field(request("POST", "/v1/nodes/register", body), "assigned_ip")
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
