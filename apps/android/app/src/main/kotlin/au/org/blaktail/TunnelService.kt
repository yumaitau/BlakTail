package au.org.blaktail

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Intent
import android.os.IBinder

/**
 * Holds the enrolment result. The packet path is not established here:
 * calling VpnService.establish() before the WireGuard engine is linked would
 * capture the phone's traffic and drop it.
 */
class TunnelService : Service() {
    override fun onBind(intent: Intent?): IBinder? = null

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val address = intent?.getStringExtra(EXTRA_ADDRESS) ?: return START_NOT_STICKY
        val manager = getSystemService(NotificationManager::class.java)
        manager.createNotificationChannel(
            NotificationChannel(CHANNEL, "BlakTail", NotificationManager.IMPORTANCE_LOW),
        )
        val notification = Notification.Builder(this, CHANNEL)
            .setContentTitle("BlakTail enrolled")
            .setContentText(address)
            .setSmallIcon(android.R.drawable.stat_sys_download_done)
            .build()
        startForeground(1, notification)
        return START_STICKY
    }

    companion object {
        const val EXTRA_ADDRESS = "address"
        private const val CHANNEL = "blaktail"
    }
}
