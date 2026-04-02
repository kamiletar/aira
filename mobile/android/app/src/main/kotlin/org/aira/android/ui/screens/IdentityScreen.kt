package org.aira.android.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.aira.android.R
import org.aira.android.repository.AiraRepository

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun IdentityScreen(repository: AiraRepository?) {
    var myAddress by remember { mutableStateOf<ByteArray?>(null) }

    LaunchedEffect(repository) {
        repository?.let {
            myAddress = it.getMyAddress()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.identity_title)) })
        }
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding).padding(16.dp)
        ) {
            Text(
                text = "Public Key",
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = myAddress?.joinToString("") { "%02x".format(it) } ?: "Loading...",
                style = MaterialTheme.typography.bodyMedium
            )
            Spacer(modifier = Modifier.height(24.dp))

            // TODO: show seed phrase backup option, QR code, safety number
            Text(
                text = "Seed Phrase Backup",
                style = MaterialTheme.typography.titleMedium
            )
            Spacer(modifier = Modifier.height(8.dp))
            Text(
                text = "Your seed phrase is stored securely on this device.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }
}
