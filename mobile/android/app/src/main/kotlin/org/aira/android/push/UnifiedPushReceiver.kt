package org.aira.android.push

import android.content.Context
import android.content.Intent
import org.aira.android.service.AiraDaemonService
import org.unifiedpush.android.connector.MessagingReceiver

/**
 * UnifiedPush receiver for decentralized push notifications.
 *
 * The relay sends a "wake-up" message (no message content passes through
 * the push server). This receiver starts the Foreground Service so the
 * Rust daemon can connect and retrieve actual messages over the P2P network.
 */
class UnifiedPushReceiver : MessagingReceiver() {

    override fun onMessage(context: Context, message: ByteArray, instance: String) {
        // Wake-up received — ensure daemon service is running
        val intent = Intent(context, AiraDaemonService::class.java)
        context.startForegroundService(intent)
    }

    override fun onNewEndpoint(context: Context, endpoint: String, instance: String) {
        // New push endpoint — register with relay
        // TODO: pass endpoint to AiraRuntime.registerPushEndpoint(endpoint)
        android.util.Log.i("UnifiedPush", "New endpoint: $endpoint")
    }

    override fun onRegistrationFailed(context: Context, instance: String) {
        android.util.Log.w("UnifiedPush", "Registration failed")
    }

    override fun onUnregistered(context: Context, instance: String) {
        android.util.Log.i("UnifiedPush", "Unregistered")
    }
}
