package au.org.blaktail

import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import kotlin.concurrent.thread

class MainActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val coordinator = EditText(this).apply { hint = "https://coord.example:8443" }
        val name = EditText(this).apply { hint = "Field phone" }
        val shareUrl = EditText(this).apply { hint = "http://10.64.0.2:5647/files/phone.txt" }
        val status = TextView(this).apply { text = "Enrol this phone, then approve it in the console." }
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
                addView(coordinator)
                addView(name)
                addView(enrol)
                addView(shareUrl)
                addView(send)
                addView(status)
            },
        )
    }
}
