package org.aira.android.push

import android.content.Intent
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage
import org.aira.android.service.AiraDaemonService

/**
 * Firebase Cloud Messaging service — fallback push notification handler.
 *
 * Like UnifiedPush, this only receives "wake-up" signals from the relay.
 * No message content passes through Google's servers.
 */
class FcmService : FirebaseMessagingService() {

    override fun onMessageReceived(message: RemoteMessage) {
        // Wake-up received — start daemon service
        val intent = Intent(this, AiraDaemonService::class.java)
        startForegroundService(intent)
    }

    override fun onNewToken(token: String) {
        // New FCM token — register with relay as fallback endpoint
        // TODO: pass token to AiraRuntime.registerPushEndpoint(fcm:$token)
        android.util.Log.i("FCM", "New token received")
    }
}
