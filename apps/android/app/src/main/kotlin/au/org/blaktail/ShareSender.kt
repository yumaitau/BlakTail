package au.org.blaktail

import java.net.HttpURLConnection
import java.net.URI

object ShareSender {
    fun send(fileUrl: String, bytes: ByteArray) {
        require(fileUrl.startsWith("http://")) { "share send stays on the overlay" }
        require(bytes.size <= 8 * 1024 * 1024) { "file is too large to send" }
        val connection = URI.create(fileUrl).toURL().openConnection() as HttpURLConnection
        connection.requestMethod = "PUT"
        connection.doOutput = true
        connection.setRequestProperty("Content-Length", bytes.size.toString())
        connection.outputStream.use { it.write(bytes) }
        if (connection.responseCode != 201 && connection.responseCode != 204) {
            error("share send failed (${connection.responseCode})")
        }
    }
}
