package org.aira.android.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import kotlinx.coroutines.launch
import org.aira.android.R
import org.aira.android.repository.AiraRepository

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    repository: AiraRepository?,
    onIdentityClick: () -> Unit
) {
    var transportMode by remember { mutableStateOf("direct") }
    val scope = rememberCoroutineScope()

    LaunchedEffect(repository) {
        repository?.let {
            transportMode = it.getTransportMode()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.tab_settings)) })
        }
    ) { padding ->
        Column(modifier = Modifier.fillMaxSize().padding(padding)) {
            // Identity
            ListItem(
                headlineContent = { Text(stringResource(R.string.identity_title)) },
                leadingContent = { Icon(Icons.Default.Fingerprint, contentDescription = null) },
                supportingContent = { Text("View seed phrase and public key") },
                modifier = Modifier.clickable(onClick = onIdentityClick)
            )
            HorizontalDivider()

            // Devices
            ListItem(
                headlineContent = { Text(stringResource(R.string.devices_title)) },
                leadingContent = { Icon(Icons.Default.Devices, contentDescription = null) },
                supportingContent = { Text("Manage linked devices") },
                modifier = Modifier.clickable { /* TODO: navigate to devices screen */ }
            )
            HorizontalDivider()

            // Transport mode
            ListItem(
                headlineContent = { Text(stringResource(R.string.transport_mode)) },
                leadingContent = { Icon(Icons.Default.Shield, contentDescription = null) },
                supportingContent = { Text("Current: $transportMode") },
                modifier = Modifier.clickable { /* TODO: transport mode selector */ }
            )
            HorizontalDivider()
        }
    }
}
