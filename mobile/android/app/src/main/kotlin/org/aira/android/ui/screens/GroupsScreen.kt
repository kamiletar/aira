package org.aira.android.ui.screens

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.GroupAdd
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import org.aira.android.R
import org.aira.android.repository.AiraRepository
import uniffi.aira_ffi.FfiGroupInfo

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupsScreen(
    repository: AiraRepository?,
    onGroupClick: (ByteArray) -> Unit,
    onCreateGroupClick: () -> Unit
) {
    var groups by remember { mutableStateOf<List<FfiGroupInfo>>(emptyList()) }

    LaunchedEffect(repository) {
        repository?.let {
            groups = it.getGroups()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(stringResource(R.string.tab_groups)) })
        },
        floatingActionButton = {
            FloatingActionButton(onClick = onCreateGroupClick) {
                Icon(Icons.Default.GroupAdd, contentDescription = stringResource(R.string.create_group))
            }
        }
    ) { padding ->
        if (groups.isEmpty()) {
            Box(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentAlignment = Alignment.Center
            ) {
                Text(
                    text = stringResource(R.string.empty_groups),
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize().padding(padding),
                contentPadding = PaddingValues(vertical = 8.dp)
            ) {
                items(groups) { group ->
                    ListItem(
                        headlineContent = { Text(group.name) },
                        supportingContent = { Text("${group.memberCount} members") },
                        modifier = Modifier.clickable {
                            onGroupClick(group.id.map { it.toByte() }.toByteArray())
                        }
                    )
                }
            }
        }
    }
}
