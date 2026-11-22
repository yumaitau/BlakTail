package au.org.blaktail

import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URI
import java.net.URLEncoder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64

/**
 * Console sign-in with PKCE (RFC 7636, S256). The console returns a one-use
 * code on blaktail://auth/callback; only this app, holding the verifier, can
 * swap it for a desktop credential. The browser session never reaches the app.
 */
object DesktopSignIn {
    const val REDIRECT_URI = "blaktail://auth/callback"

    data class Pending(val verifier: String, val state: String, val console: String)

    private val random = SecureRandom()

    fun randomToken(): String {
        val bytes = ByteArray(32).also(random::nextBytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }

    fun challenge(verifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(verifier.toByteArray(Charsets.US_ASCII))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    fun start(console: String): Pending = Pending(randomToken(), randomToken(), console.trimEnd('/'))

    fun startUrl(pending: Pending): String {
        fun q(value: String) = URLEncoder.encode(value, "UTF-8")
        return "${pending.console}/desktop/auth" +
            "?redirect_uri=${q(REDIRECT_URI)}" +
            "&state=${q(pending.state)}" +
            "&code_challenge=${q(challenge(pending.verifier))}" +
            "&code_challenge_method=S256"
    }

    /** The code from the callback, or null when it is not ours, was cancelled, or `state` differs. */
    fun code(scheme: String?, host: String?, path: String?, query: (String) -> String?, expectedState: String?): String? {
        if (scheme != "blaktail" || host != "auth" || path != "/callback") return null
        val state = query("state")
        if (expectedState.isNullOrEmpty() || state != expectedState) return null
        if (query("error") != null) return null
        return query("code")?.takeIf { it.isNotEmpty() }
    }

    /** POST /api/desktop/auth/token; returns the `btd_` credential. */
    fun exchange(pending: Pending, code: String): String {
        val url = URI("${pending.console}/api/desktop/auth/token").toURL()
        val connection = url.openConnection() as HttpURLConnection
        connection.requestMethod = "POST"
        connection.connectTimeout = 15_000
        connection.readTimeout = 15_000
        connection.doOutput = true
        connection.setRequestProperty("content-type", "application/json")
        val body = JSONObject()
            .put("code", code)
            .put("code_verifier", pending.verifier)
            .put("redirect_uri", REDIRECT_URI)
            .toString()
        connection.outputStream.use { it.write(body.toByteArray()) }
        val status = connection.responseCode
        val stream = if (status in 200..299) connection.inputStream else connection.errorStream
        val text = stream?.bufferedReader()?.readText().orEmpty()
        if (status !in 200..299) {
            val detail = runCatching { JSONObject(text).optString("error_description") }.getOrNull()
            error(detail?.ifBlank { null } ?: "console returned $status")
        }
        return JSONObject(text).getString("token")
    }
}
