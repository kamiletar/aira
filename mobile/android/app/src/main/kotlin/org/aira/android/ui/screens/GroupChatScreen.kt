package org.aira.android.ui.screens

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.Send
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch
import org.aira.android.R
import org.aira.android.repository.AiraRepository
import org.aira.android.ui.components.MessageBubble
import uniffi.aira_ffi.FfiMessage

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun GroupChatScreen(
    repository: AiraRepository?,
    groupIdHex: String
) {
    var messages by remember { mutableStateOf<List<FfiMessage>>(emptyList()) }
    var groupName by remember { mutableStateOf("Group") }
    var inputText by remember { mutableStateOf("") }
    val scope = rememberCoroutineScope()

    val groupId = remember(groupIdHex) {
        groupIdHex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    }

    LaunchedEffect(repository, groupIdHex) {
        repository?.let {
            try {
                val info = it.getGroupInfo(groupId)
                groupName = info.name
            } catch (_: Exception) { }
            messages = it.getGroupHistory(groupId, 100u)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(title = { Text(groupName) })
        }
    ) { padding ->
        Column(
            modifier = Modifier.fillMaxSize().padding(padding)
        ) {
            LazyColumn(
                modifier = Modifier.weight(1f).fillMaxWidth(),
                contentPadding = PaddingValues(horizontal = 8.dp, vertical = 4.dp),
                reverseLayout = true
            ) {
                items(messages.reversed()) { message ->
                    MessageBubble(
                        text = String(message.payload.map { it.toByte() }.toByteArray()),
                        isOutgoing = message.senderIsSelf,
                        timestamp = message.timestampMicros
                    )
                }
            }

            Row(
                modifier = Modifier.fillMaxWidth().padding(8.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                OutlinedTextField(
                    value = inputText,
                    onValueChange = { inputText = it },
                    modifier = Modifier.weight(1f),
                    placeholder = { Text("Message to group...") },
                    maxLines = 4
                )
                Spacer(modifier = Modifier.width(8.dp))
                IconButton(
                    onClick = {
                        if (inputText.isNotBlank()) {
                            val text = inputText
                            inputText = ""
                            scope.launch {
                                repository?.sendGroupMessage(groupId, text)
                                repository?.let {
                                    messages = it.getGroupHistory(groupId, 100u)
                                }
                            }
                        }
                    }
                ) {
                    Icon(Icons.AutoMirrored.Filled.Send, contentDescription = "Send")
                }
            }
        }
    }
}
