package au.org.blaktail

import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {
    private lateinit var status: TextView
    private lateinit var coordinator: EditText

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val console = EditText(this).apply { hint = "https://console.example" }
        coordinator = EditText(this).apply { hint = "https://coord.example:8443" }
        val name = EditText(this).apply { hint = "Field phone" }
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
                        val started = client.start(device, client.newPublicKey())
                        runOnUiThread {
                            status.text = "Approve ${started.userCode}\n${started.verificationUrl}"
                        }
                    }.onFailure { error ->
                        runOnUiThread { status.text = error.message ?: "Enrolment failed" }
                    }
                }
            }
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
}
