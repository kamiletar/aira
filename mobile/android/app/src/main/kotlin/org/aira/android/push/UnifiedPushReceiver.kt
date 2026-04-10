package org.aira.android.push

import android.content.Context
import android.content.Intent
import org.aira.android.service.AiraDaemonService
import org.unifiedpush.android.connector.MessagingReceiver
import org.unifiedpush.android.connector.data.PushEndpoint
import org.unifiedpush.android.connector.data.PushMessage
import org.unifiedpush.android.connector.FailedReason

/**
 * UnifiedPush receiver for decentralized push notifications.
 *
 * The relay sends a "wake-up" message (no message content passes through
 * the push server). This receiver starts the Foreground Service so the
 * Rust daemon can connect and retrieve actual messages over the P2P network.
 */
class UnifiedPushReceiver : MessagingReceiver() {

    override fun onMessage(context: Context, message: PushMessage, instance: String) {
        // Wake-up received — ensure daemon service is running
        val intent = Intent(context, AiraDaemonService::class.java)
        context.startForegroundService(intent)
    }

    override fun onNewEndpoint(context: Context, endpoint: PushEndpoint, instance: String) {
        // New push endpoint — register with relay
        // TODO: pass endpoint.url to AiraRuntime.registerPushEndpoint(endpoint)
        android.util.Log.i("UnifiedPush", "New endpoint: ${endpoint.url}")
    }

    override fun onRegistrationFailed(context: Context, reason: FailedReason, instance: String) {
        android.util.Log.w("UnifiedPush", "Registration failed: $reason")
    }

    override fun onUnregistered(context: Context, instance: String) {
        android.util.Log.i("UnifiedPush", "Unregistered")
    }
}
