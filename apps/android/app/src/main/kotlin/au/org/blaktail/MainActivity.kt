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
                val pending = DesktopSignIn.start(console.text.toString())
                // Kept until the callback arrives; the activity may be recreated meanwhile.
                getSharedPreferences("blaktail", MODE_PRIVATE).edit()
                    .putString(PENDING_VERIFIER, pending.verifier)
                    .putString(PENDING_STATE, pending.state)
                    .putString(PENDING_CONSOLE, pending.console)
                    .apply()
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(DesktopSignIn.startUrl(pending))))
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
                        val map = client.peers(joined.id, joined.nodeToken)
                        getSharedPreferences("blaktail", MODE_PRIVATE).edit()
                            .putString("address", joined.address)
                            .putString("nodeId", joined.id)
                            .putString("nodeToken", Secrets.seal(joined.nodeToken))
                            .putString("coordinator", coordinator.text.toString())
                            .putStringSet("peers", map.peers.toSet())
                            .putString("policy", map.policy)
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
        val prefs = getSharedPreferences("blaktail", MODE_PRIVATE)
        val verifier = prefs.getString(PENDING_VERIFIER, null)
        val expectedState = prefs.getString(PENDING_STATE, null)
        val consoleBase = prefs.getString(PENDING_CONSOLE, null)
        // Nothing pending: an unsolicited or replayed callback (or a re-delivered intent).
        if (expectedState == null) return
        val code = DesktopSignIn.code(data.scheme, data.host, data.path, data::getQueryParameter, expectedState)
        if (code == null || verifier == null || consoleBase == null) {
            // A callback for our request that was cancelled ends it; anything else is ignored.
            if (data.getQueryParameter("state") == expectedState) {
                clearPending(prefs)
                status.text = "Sign-in did not complete. Try Sign in again."
            }
            return
        }
        // One attempt per request: a replayed callback finds nothing pending.
        clearPending(prefs)
        val pending = DesktopSignIn.Pending(verifier, expectedState, consoleBase)
        thread {
            runCatching { DesktopSignIn.exchange(pending, code) }
                .onSuccess { token ->
                    prefs.edit().putString("session", Secrets.seal(token)).putString("console", consoleBase).apply()
                    runOnUiThread {
                        status.text = "Signed in. Enrol this phone, then approve the code in the console."
                    }
                }
                .onFailure { error ->
                    runOnUiThread { status.text = error.message ?: "Sign-in failed" }
                }
        }
    }

    private fun clearPending(prefs: android.content.SharedPreferences) {
        prefs.edit().remove(PENDING_VERIFIER).remove(PENDING_STATE).remove(PENDING_CONSOLE).apply()
    }

    companion object {
        private const val PENDING_VERIFIER = "signInVerifier"
        private const val PENDING_STATE = "signInState"
        private const val PENDING_CONSOLE = "signInConsole"
    }

    private fun privateKey(): ByteArray {
        val prefs = getSharedPreferences("blaktail", MODE_PRIVATE)
        Secrets.read(prefs, "privateKey")?.let { return Base64.decode(it, Base64.NO_WRAP) }
        val created = ByteArray(32).also(SecureRandom()::nextBytes)
        prefs.edit()
            .putString("privateKey", Secrets.seal(Base64.encodeToString(created, Base64.NO_WRAP)))
            .apply()
        return created
    }

    private fun connectTunnel() {
        val prefs = getSharedPreferences("blaktail", MODE_PRIVATE)
        val address = prefs.getString("address", null)
        val key = Secrets.read(prefs, "privateKey")
        if (address == null || key == null) {
            status.text = "Join this phone before connecting"
            return
        }
        val peers = ArrayList(prefs.getStringSet("peers", emptySet()) ?: emptySet())
        tunnelIntent = Intent(this, TunnelService::class.java).apply {
            putExtra(TunnelService.EXTRA_ADDRESS, address)
            putExtra(TunnelService.EXTRA_PRIVATE_KEY, Base64.decode(key, Base64.NO_WRAP))
            putStringArrayListExtra(TunnelService.EXTRA_PEERS, peers)
            putExtra(TunnelService.EXTRA_POLICY, prefs.getString("policy", null))
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
