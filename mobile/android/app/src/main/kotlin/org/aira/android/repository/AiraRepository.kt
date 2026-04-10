package org.aira.android.repository

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import uniffi.aira_ffi.*

/**
 * Repository wrapping the UniFFI [AiraRuntime].
 *
 * Provides a coroutine-friendly API by dispatching FFI calls to [Dispatchers.IO].
 * The runtime instance is created and owned by [AiraDaemonService]; Activities
 * obtain this repository via the bound service.
 */
class AiraRepository(private val runtime: AiraRuntime) {

    // ── Contacts ──────────────────────────────────────────────────────

    suspend fun getContacts(): List<FfiContact> = withContext(Dispatchers.IO) {
        runtime.getContacts()
    }

    suspend fun addContact(pubkey: ByteArray, alias: String) = withContext(Dispatchers.IO) {
        runtime.addContact(pubkey, alias)
    }

    suspend fun removeContact(pubkey: ByteArray) = withContext(Dispatchers.IO) {
        runtime.removeContact(pubkey)
    }

    // ── Messages ──────────────────────────────────────────────────────

    suspend fun sendMessage(to: ByteArray, text: String) = withContext(Dispatchers.IO) {
        runtime.sendMessage(to, text)
    }

    suspend fun getHistory(contact: ByteArray, limit: UInt): List<FfiMessage> =
        withContext(Dispatchers.IO) {
            runtime.getHistory(contact, limit)
        }

    suspend fun getMyAddress(): ByteArray = withContext(Dispatchers.IO) {
        runtime.getMyAddress()
    }

    // ── Groups ────────────────────────────────────────────────────────

    suspend fun createGroup(name: String, members: List<ByteArray>): ByteArray =
        withContext(Dispatchers.IO) {
            runtime.createGroup(name, members)
        }

    suspend fun getGroups(): List<FfiGroupInfo> = withContext(Dispatchers.IO) {
        runtime.getGroups()
    }

    suspend fun getGroupInfo(groupId: ByteArray): FfiGroupDetail =
        withContext(Dispatchers.IO) {
            runtime.getGroupInfo(groupId)
        }

    suspend fun sendGroupMessage(groupId: ByteArray, text: String) =
        withContext(Dispatchers.IO) {
            runtime.sendGroupMessage(groupId, text)
        }

    suspend fun getGroupHistory(groupId: ByteArray, limit: UInt): List<FfiMessage> =
        withContext(Dispatchers.IO) {
            runtime.getGroupHistory(groupId, limit)
        }

    // ── Devices ───────────────────────────────────────────────────────

    suspend fun getDevices(): List<FfiDeviceInfo> = withContext(Dispatchers.IO) {
        runtime.getDevices()
    }

    suspend fun generateLinkCode(): String = withContext(Dispatchers.IO) {
        runtime.generateLinkCode()
    }

    // ── Transport ─────────────────────────────────────────────────────

    suspend fun getTransportMode(): String = withContext(Dispatchers.IO) {
        runtime.getTransportMode()
    }

    suspend fun setTransportMode(mode: String) = withContext(Dispatchers.IO) {
        runtime.setTransportMode(mode)
    }

    // ── Lifecycle ─────────────────────────────────────────────────────

    fun shutdown() {
        runtime.shutdown()
    }

    /**
     * Register an event listener for async events from the Rust runtime.
     */
    fun setEventListener(listener: AiraEventListener) {
        runtime.setEventListener(listener)
    }
}
