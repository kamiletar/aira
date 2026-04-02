package org.aira.android.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.aira.android.R
import org.aira.android.repository.AiraRepository

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AddContactScreen(
    repository: AiraRepository?,
    onContactAdded: () -> Unit
) {
    var pubkeyHex by remember { mutableStateOf("") }
    var alias by remember { mutableStateOf("") }
    var error by remember { mutableStateOf<String?>(null) }
    val scope = rememberCoroutineScope()

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.add_contact)) })
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
        ) {
            OutlinedTextField(
                value = alias,
                onValueChange = { alias = it },
                label = { Text("Display Name") },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true
            )
            Spacer(modifier = Modifier.height(12.dp))

            OutlinedTextField(
                value = pubkeyHex,
                onValueChange = { pubkeyHex = it },
                label = { Text("Public Key (hex)") },
                modifier = Modifier.fillMaxWidth(),
                maxLines = 3
            )
            Spacer(modifier = Modifier.height(16.dp))

            error?.let {
                Text(
                    text = it,
                    color = MaterialTheme.colorScheme.error,
                    style = MaterialTheme.typography.bodySmall
                )
                Spacer(modifier = Modifier.height(8.dp))
            }

            Button(
                onClick = {
                    error = null
                    scope.launch {
                        try {
                            val pubkey = pubkeyHex.trim()
                                .chunked(2)
                                .map { it.toInt(16).toByte() }
                                .toByteArray()
                            repository?.addContact(pubkey, alias.trim())
                            onContactAdded()
                        } catch (e: Exception) {
                            error = e.message ?: "Failed to add contact"
                        }
                    }
                },
                modifier = Modifier.fillMaxWidth(),
                enabled = pubkeyHex.isNotBlank() && alias.isNotBlank()
            ) {
                Text("Add Contact")
            }
        }
    }
}
