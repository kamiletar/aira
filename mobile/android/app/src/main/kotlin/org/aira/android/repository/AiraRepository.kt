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
        runtime.addContact(pubkey.toList().map { it.toUByte() }, alias)
    }

    suspend fun removeContact(pubkey: ByteArray) = withContext(Dispatchers.IO) {
        runtime.removeContact(pubkey.toList().map { it.toUByte() })
    }

    // ── Messages ──────────────────────────────────────────────────────

    suspend fun sendMessage(to: ByteArray, text: String) = withContext(Dispatchers.IO) {
        runtime.sendMessage(to.toList().map { it.toUByte() }, text)
    }

    suspend fun getHistory(contact: ByteArray, limit: UInt): List<FfiMessage> =
        withContext(Dispatchers.IO) {
            runtime.getHistory(contact.toList().map { it.toUByte() }, limit)
        }

    suspend fun getMyAddress(): ByteArray = withContext(Dispatchers.IO) {
        runtime.getMyAddress().map { it.toByte() }.toByteArray()
    }

    // ── Groups ────────────────────────────────────────────────────────

    suspend fun createGroup(name: String, members: List<ByteArray>): ByteArray =
        withContext(Dispatchers.IO) {
            val membersList = members.map { it.toList().map { b -> b.toUByte() } }
            runtime.createGroup(name, membersList).map { it.toByte() }.toByteArray()
        }

    suspend fun getGroups(): List<FfiGroupInfo> = withContext(Dispatchers.IO) {
        runtime.getGroups()
    }

    suspend fun getGroupInfo(groupId: ByteArray): FfiGroupDetail =
        withContext(Dispatchers.IO) {
            runtime.getGroupInfo(groupId.toList().map { it.toUByte() })
        }

    suspend fun sendGroupMessage(groupId: ByteArray, text: String) =
        withContext(Dispatchers.IO) {
            runtime.sendGroupMessage(groupId.toList().map { it.toUByte() }, text)
        }

    suspend fun getGroupHistory(groupId: ByteArray, limit: UInt): List<FfiMessage> =
        withContext(Dispatchers.IO) {
            runtime.getGroupHistory(groupId.toList().map { it.toUByte() }, limit)
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
