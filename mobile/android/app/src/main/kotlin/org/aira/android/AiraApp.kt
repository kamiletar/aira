package org.aira.android

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.os.Build

/**
 * Application class for Aira.
 *
 * Creates notification channels required by the Foreground Service and
 * message notifications.
 */
class AiraApp : Application() {

    override fun onCreate() {
        super.onCreate()
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        val manager = getSystemService(NotificationManager::class.java)

        // Daemon service channel (low priority — persistent, silent)
        val serviceChannel = NotificationChannel(
            CHANNEL_SERVICE,
            getString(R.string.daemon_notification_channel),
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Keeps the secure messaging service running"
            setShowBadge(false)
        }

        // Message notification channel (high priority)
        val messageChannel = NotificationChannel(
            CHANNEL_MESSAGES,
            getString(R.string.message_notification_channel),
            NotificationManager.IMPORTANCE_HIGH
        ).apply {
            description = "New message notifications"
        }

        manager.createNotificationChannel(serviceChannel)
        manager.createNotificationChannel(messageChannel)
    }

    companion object {
        const val CHANNEL_SERVICE = "aira_service"
        const val CHANNEL_MESSAGES = "aira_messages"
    }
}
