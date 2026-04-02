package org.aira.android.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PersonAdd
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.aira.android.R
import org.aira.android.repository.AiraRepository
import uniffi.aira_ffi.FfiContact

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ContactsScreen(
    repository: AiraRepository?,
    onContactClick: (ByteArray) -> Unit,
    onAddContactClick: () -> Unit
) {
    var contacts by remember { mutableStateOf<List<FfiContact>>(emptyList()) }
    val scope = rememberCoroutineScope()

    LaunchedEffect(repository) {
        repository?.let {
            contacts = it.getContacts()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.tab_contacts)) })
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onAddContactClick) {
                Icon(Icons.Default.PersonAdd, contentDescription = stringResource(R.string.add_contact))
            }
        }
    ) { padding ->
        if (contacts.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = stringResource(R.string.empty_contacts),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(vertical = 8.dp)
            ) {
                items(contacts, key = { it.pubkey.hashCode() }) { contact ->
                    ListItem(
                        headlineContent = { Text(contact.alias) },
                        supportingContent = {
                            Text(
                                contact.pubkey.take(8).joinToString("") { "%02x".format(it) } + "...",
                                style = MaterialTheme.typography.bodySmall
                            )
                        },
                        modifier = Modifier.clickable {
                            onContactClick(contact.pubkey.map { it.toByte() }.toByteArray())
                        }
                    )
                }
            }
        }
    }
}
