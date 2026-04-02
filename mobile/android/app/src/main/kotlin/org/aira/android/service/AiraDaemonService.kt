package org.aira.android.service

import android.app.Notification
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.os.Binder
import android.os.IBinder
import androidx.core.app.NotificationCompat
import org.aira.android.AiraApp
import org.aira.android.MainActivity
import org.aira.android.R
import org.aira.android.repository.AiraRepository
import uniffi.aira_ffi.AiraRuntime

/**
 * Foreground Service that hosts the Aira daemon (Rust runtime) in-process.
 *
 * The daemon is NOT a separate process on Android — it runs embedded via UniFFI.
 * This service keeps it alive when the app is backgrounded.
 *
 * Activities bind to this service to access the [AiraRepository].
 */
class AiraDaemonService : Service() {

    private var runtime: AiraRuntime? = null
    private var repository: AiraRepository? = null

    private val binder = DaemonBinder()

    inner class DaemonBinder : Binder() {
        fun getRepository(): AiraRepository? = repository
    }

    override fun onCreate() {
        super.onCreate()
        startForeground(NOTIFICATION_ID, createNotification())
        initRuntime()
    }

    private fun initRuntime() {
        try {
            val dataDir = filesDir.resolve("aira").absolutePath
            // TODO: retrieve seed phrase from secure storage (Android Keystore)
            // For now, use a placeholder — real implementation needs secure seed management
            val seedPhrase = getSharedPreferences("aira_prefs", MODE_PRIVATE)
                .getString("seed_phrase", null)
                ?: return // No seed configured yet — user must set up identity first

            val rt = AiraRuntime(dataDir, seedPhrase)
            runtime = rt
            repository = AiraRepository(rt)
        } catch (e: Exception) {
            android.util.Log.e(TAG, "Failed to initialize Aira runtime", e)
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onDestroy() {
        runtime?.shutdown()
        runtime = null
        repository = null
        super.onDestroy()
    }

    private fun createNotification(): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, AiraApp.CHANNEL_SERVICE)
            .setContentTitle(getString(R.string.daemon_notification_title))
            .setContentText(getString(R.string.daemon_notification_text))
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .build()
    }

    companion object {
        private const val TAG = "AiraDaemonService"
        private const val NOTIFICATION_ID = 1
    }
}
