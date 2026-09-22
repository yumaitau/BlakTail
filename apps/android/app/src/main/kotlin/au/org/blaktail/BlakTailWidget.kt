package au.org.blaktail

import android.app.PendingIntent
import android.appwidget.AppWidgetManager
import android.appwidget.AppWidgetProvider
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Base64
import android.widget.RemoteViews

class BlakTailWidget : AppWidgetProvider() {
    override fun onUpdate(context: Context, manager: AppWidgetManager, ids: IntArray) {
        update(context, manager, ids)
    }

    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action == ACTION_TOGGLE) {
            toggle(context)
        }
        super.onReceive(context, intent)
        val manager = AppWidgetManager.getInstance(context)
        val ids = manager.getAppWidgetIds(ComponentName(context, BlakTailWidget::class.java))
        update(context, manager, ids)
    }

    companion object {
        const val ACTION_TOGGLE = "au.org.blaktail.widget.TOGGLE"
        const val PREFS = "blaktail"
        const val KEY_RUNNING = "tunnelRunning"

        fun publish(context: Context, running: Boolean) {
            context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(KEY_RUNNING, running)
                .apply()
            refresh(context)
        }

        fun refresh(context: Context) {
            val manager = AppWidgetManager.getInstance(context)
            val ids = manager.getAppWidgetIds(ComponentName(context, BlakTailWidget::class.java))
            update(context, manager, ids)
        }

        fun update(context: Context, manager: AppWidgetManager, ids: IntArray) {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val address = prefs.getString("address", null).orEmpty()
            val joined = address.isNotBlank() && prefs.contains("privateKey")
            val running = prefs.getBoolean(KEY_RUNNING, false) && joined
            val views = RemoteViews(context.packageName, R.layout.blaktail_widget)
            views.setTextViewText(
                R.id.widget_status,
                when {
                    running -> context.getString(R.string.widget_connected)
                    joined -> context.getString(R.string.widget_off)
                    else -> context.getString(R.string.widget_join)
                },
            )
            views.setTextViewText(R.id.widget_address, if (joined) address else "")
            views.setTextViewText(
                R.id.widget_toggle,
                context.getString(if (running) R.string.widget_disconnect else R.string.widget_connect),
            )
            val toggle = PendingIntent.getBroadcast(
                context,
                0,
                Intent(context, BlakTailWidget::class.java).setAction(ACTION_TOGGLE),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            views.setOnClickPendingIntent(R.id.widget_toggle, toggle)
            val open = PendingIntent.getActivity(
                context,
                1,
                Intent(context, MainActivity::class.java),
                PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE,
            )
            views.setOnClickPendingIntent(R.id.widget_root, open)
            ids.forEach { manager.updateAppWidget(it, views) }
        }

        private fun toggle(context: Context) {
            val prefs = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val running = prefs.getBoolean(KEY_RUNNING, false)
            if (running) {
                context.stopService(Intent(context, TunnelService::class.java))
                publish(context, false)
                return
            }
            val launch = TunnelService.launchIntent(context)
            val consent = VpnService.prepare(context)
            when {
                launch == null || consent != null -> {
                    val activity = consent ?: Intent(context, MainActivity::class.java)
                    activity.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    context.startActivity(activity)
                }
                else -> context.startForegroundService(launch)
            }
        }
    }
}

fun TunnelService.Companion.launchIntent(context: Context): Intent? {
    val prefs = context.getSharedPreferences(BlakTailWidget.PREFS, Context.MODE_PRIVATE)
    val address = prefs.getString("address", null) ?: return null
    val key = prefs.getString("privateKey", null) ?: return null
    val peers = ArrayList(prefs.getStringSet("peers", emptySet()) ?: emptySet())
    return Intent(context, TunnelService::class.java).apply {
        putExtra(TunnelService.EXTRA_ADDRESS, address)
        putExtra(TunnelService.EXTRA_PRIVATE_KEY, Base64.decode(key, Base64.NO_WRAP))
        putStringArrayListExtra(TunnelService.EXTRA_PEERS, peers)
    }
}
