package org.aira.android

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.ServiceConnection
import android.os.Bundle
import android.os.IBinder
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import org.aira.android.repository.AiraRepository
import org.aira.android.service.AiraDaemonService
import org.aira.android.ui.theme.AiraTheme
import org.aira.android.ui.navigation.AiraNavGraph

/**
 * Single Activity hosting the Jetpack Compose UI.
 *
 * Binds to [AiraDaemonService] to access the [AiraRepository].
 */
class MainActivity : ComponentActivity() {

    private var repository by mutableStateOf<AiraRepository?>(null)

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = service as AiraDaemonService.DaemonBinder
            repository = binder.getRepository()
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            repository = null
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()

        // Start and bind to daemon service
        val intent = Intent(this, AiraDaemonService::class.java)
        startForegroundService(intent)
        bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)

        setContent {
            AiraTheme {
                AiraNavGraph(repository = repository)
            }
        }
    }

    override fun onDestroy() {
        unbindService(serviceConnection)
        super.onDestroy()
    }
}
