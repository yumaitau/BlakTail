package au.org.blaktail

import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.util.Base64
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import java.security.SecureRandom
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {
    private lateinit var status: TextView
    private lateinit var coordinator: EditText
    private lateinit var deviceName: EditText
    private var tunnelIntent: Intent? = null
    private val vpnReady = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        if (result.resultCode != RESULT_OK) return@registerForActivityResult
        tunnelIntent?.let { startForegroundService(it) }
        status.text = "Tunnel started"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val console = EditText(this).apply { hint = "https://console.example" }
        coordinator = EditText(this).apply { hint = "https://coord.example:8443" }
        deviceName = EditText(this).apply { hint = "Field phone" }
        val name = deviceName
        val shareUrl = EditText(this).apply { hint = "http://10.64.0.2:5647/files/phone.txt" }
        status = TextView(this).apply {
            text = "Sign in with the organisation account. Group rules are enforced by the console."
        }
        val signIn = Button(this).apply {
            text = "Sign in"
            setOnClickListener {
                val base = console.text.toString().trimEnd('/')
                val uri = Uri.parse("$base/desktop/auth?redirect_uri=blaktail://auth/callback")
                startActivity(Intent(Intent.ACTION_VIEW, uri))
            }
        }
        val enrol = Button(this).apply {
            text = "Ask to join"
            setOnClickListener {
                val client = EnrolmentClient(coordinator.text.toString())
                val device = name.text.toString().ifBlank { "Android" }
                thread {
                    runCatching {
                        val secret = privateKey()
                        val publicKey = Base64.encodeToString(NativeTunnel.publicKey(secret), Base64.NO_WRAP)
                        val started = client.start(device, publicKey)
                        runOnUiThread {
                            status.text = "Approve ${started.userCode}\n${started.verificationUrl}"
                        }
                        client.awaitApproved(started.deviceCode)
                        val joined = client.register(started.deviceCode, device, publicKey)
                        val peers = client.peers(joined.id, joined.nodeToken)
                        getSharedPreferences("blaktail", MODE_PRIVATE).edit()
                            .putString("address", joined.address)
                            .putString("nodeId", joined.id)
                            .putString("nodeToken", joined.nodeToken)
                            .putStringSet("peers", peers.toSet())
                            .apply()
                        runOnUiThread {
                            status.text = "Joined as ${joined.address}. Connect to start the tunnel."
                            BlakTailWidget.refresh(this@MainActivity)
                        }
                    }.onFailure { error ->
                        runOnUiThread { status.text = error.message ?: "Enrolment failed" }
                    }
                }
            }
        }
        val connect = Button(this).apply {
            text = "Connect"
            setOnClickListener { connectTunnel() }
        }
        val send = Button(this).apply {
            text = "Send a note"
            setOnClickListener {
                thread {
                    runCatching {
                        ShareSender.send(shareUrl.text.toString(), "hello from android".toByteArray())
                    }.onFailure { error ->
                        runOnUiThread { status.text = error.message ?: "Send failed" }
                    }
                }
            }
        }
        setContentView(
            LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                addView(console)
                addView(signIn)
                addView(coordinator)
                addView(name)
                addView(enrol)
                addView(connect)
                addView(shareUrl)
                addView(send)
                addView(status)
            },
        )
        acceptCallback(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        acceptCallback(intent)
    }

    private fun acceptCallback(intent: Intent?) {
        val data = intent?.data ?: return
        if (data.scheme != "blaktail") return
        val token = data.fragment
            ?.split('&')
            ?.firstNotNullOfOrNull { part ->
                part.removePrefix("token=").takeIf { part.startsWith("token=") }
            }
            ?.let(Uri::decode)
            ?: return
        status.text = "Signed in. Enrol this phone, then approve the code in the console."
        getSharedPreferences("blaktail", MODE_PRIVATE).edit().putString("session", token).apply()
    }

    private fun privateKey(): ByteArray {
        val prefs = getSharedPreferences("blaktail", MODE_PRIVATE)
        prefs.getString("privateKey", null)?.let { return Base64.decode(it, Base64.NO_WRAP) }
        val created = ByteArray(32).also(SecureRandom()::nextBytes)
        prefs.edit().putString("privateKey", Base64.encodeToString(created, Base64.NO_WRAP)).apply()
        return created
    }

    private fun connectTunnel() {
        val prefs = getSharedPreferences("blaktail", MODE_PRIVATE)
        val address = prefs.getString("address", null)
        val key = prefs.getString("privateKey", null)
        if (address == null || key == null) {
            status.text = "Join this phone before connecting"
            return
        }
        val peers = ArrayList(prefs.getStringSet("peers", emptySet()) ?: emptySet())
        tunnelIntent = Intent(this, TunnelService::class.java).apply {
            putExtra(TunnelService.EXTRA_ADDRESS, address)
            putExtra(TunnelService.EXTRA_PRIVATE_KEY, Base64.decode(key, Base64.NO_WRAP))
            putStringArrayListExtra(TunnelService.EXTRA_PEERS, peers)
        }
        val prepare = VpnService.prepare(this)
        if (prepare == null) {
            startForegroundService(tunnelIntent)
            status.text = "Tunnel started"
            BlakTailWidget.refresh(this)
        } else {
            vpnReady.launch(prepare)
        }
    }
}
