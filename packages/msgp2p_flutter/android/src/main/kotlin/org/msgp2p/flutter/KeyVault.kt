package org.msgp2p.flutter

import android.content.Context
import android.os.Handler
import android.os.Looper
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.io.RandomAccessFile
import java.security.KeyStore
import java.util.concurrent.Executors
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Error with a channel code the Dart `PlatformKeyVault` maps: `CORRUPTED` or `UNAVAILABLE`. */
class KeyVaultException(val code: String, message: String) : Exception(message)

/** The key that seals the seeds: the Android Keystore in the app, a software key in JVM tests. */
interface SealingKeys {
    fun get(alias: String): SecretKey?
    fun create(alias: String): SecretKey
    fun delete(alias: String)
}

class AndroidKeystoreKeys : SealingKeys {
    private val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }

    override fun get(alias: String): SecretKey? = store.getKey(alias, null) as SecretKey?

    override fun create(alias: String): SecretKey {
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(
            KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256)
                .build()
        )
        return generator.generateKey()
    }

    override fun delete(alias: String) {
        if (store.containsAlias(alias)) store.deleteEntry(alias)
    }
}

/**
 * The device identity seeds (proposal 0001, step 2b; Discussion #10), opaque bytes sealed with AES-256-GCM
 * under a non-exportable key, in `<dir>/keyvault-<name>.bin` as `[1][IV 12][ciphertext + tag]` with the
 * key alias as AAD. The file is written to a temporary file and renamed; a lock inside the process and a
 * file lock across processes make concurrent first calls create one identity.
 */
class KeyVaultStore(private val dir: File, private val keys: SealingKeys) {
    /** The stored seeds and false, or else [candidate] (now stored) and true. */
    fun loadOrCreate(name: String, candidate: ByteArray): Pair<ByteArray, Boolean> = locked(name) {
        val file = File(dir, "keyvault-$name.bin")
        if (file.exists()) return@locked Pair(open(alias(name), file.readBytes()), false)
        keys.delete(alias(name)) // a key without its file is left over from an interrupted create or erase
        val sealed = seal(keys.create(alias(name)), alias(name), candidate)
        val tmp = File(dir, "keyvault-$name.tmp")
        FileOutputStream(tmp).use {
            it.write(sealed)
            it.fd.sync()
        }
        if (!tmp.renameTo(file)) throw IOException("cannot rename the vault file")
        Pair(candidate, true)
    }

    /** The file first: a key left without its file is removed by the next create. */
    fun erase(name: String) = locked(name) {
        File(dir, "keyvault-$name.bin").delete()
        keys.delete(alias(name))
    }

    private fun open(alias: String, bytes: ByteArray): ByteArray {
        if (bytes.size < 1 + IV_BYTES + TAG_BYTES || bytes[0] != FORMAT) {
            throw KeyVaultException("CORRUPTED", "the vault file is malformed")
        }
        // Keystore keys never leave the device: a file without its key, or sealed by another key, came from
        // another device or install (a backup or transfer that did not respect no_backup).
        val key = keys.get(alias)
            ?: throw KeyVaultException("UNAVAILABLE", "the vault file has no key on this device")
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(TAG_BYTES * 8, bytes, 1, IV_BYTES))
        cipher.updateAAD(alias.toByteArray())
        return try {
            cipher.doFinal(bytes, 1 + IV_BYTES, bytes.size - 1 - IV_BYTES)
        } catch (e: AEADBadTagException) {
            throw KeyVaultException("UNAVAILABLE", "the vault file was sealed by another key")
        }
    }

    private fun seal(key: SecretKey, alias: String, plain: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(Cipher.ENCRYPT_MODE, key) // the provider picks a random IV
        cipher.updateAAD(alias.toByteArray())
        val sealed = cipher.doFinal(plain)
        check(cipher.iv.size == IV_BYTES)
        return byteArrayOf(FORMAT) + cipher.iv + sealed
    }

    private fun <T> locked(name: String, action: () -> T): T {
        require(NAME.matches(name)) { "bad vault name" }
        synchronized(LOCK) {
            dir.mkdirs()
            RandomAccessFile(File(dir, "keyvault-$name.lock"), "rw").channel.use { channel ->
                channel.lock().use { return action() }
            }
        }
    }

    private fun alias(name: String) = "org.msgp2p.keyvault.$name"

    companion object {
        val NAME = Regex("[A-Za-z0-9_-]{1,64}")
        private const val FORMAT: Byte = 1
        private const val IV_BYTES = 12
        private const val TAG_BYTES = 16
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private val LOCK = Any()
    }
}

/** `org.msgp2p/key_vault`: runs the vault off the main thread, one call at a time. */
class KeyVaultChannel(context: Context) : MethodChannel.MethodCallHandler {
    private val store by lazy {
        KeyVaultStore(File(context.noBackupFilesDir, "msgp2p"), AndroidKeystoreKeys())
    }
    private val main = Handler(Looper.getMainLooper())

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        val name = call.argument<String>("name")
        if (name == null || !KeyVaultStore.NAME.matches(name)) {
            result.error("BAD_ARGS", "missing or bad vault name", null)
            return
        }
        when (call.method) {
            "loadOrCreate" -> {
                val candidate = call.argument<ByteArray>("candidate")
                if (candidate == null) {
                    result.error("BAD_ARGS", "missing candidate", null)
                    return
                }
                run(result) {
                    val (seeds, created) = store.loadOrCreate(name, candidate)
                    mapOf("seeds" to seeds, "created" to created)
                }
            }
            "erase" -> run(result) { store.erase(name); null }
            else -> result.notImplemented()
        }
    }

    private fun run(result: MethodChannel.Result, action: () -> Any?) {
        EXECUTOR.execute {
            try {
                val reply = action()
                main.post { result.success(reply) }
            } catch (e: KeyVaultException) {
                main.post { result.error(e.code, e.message, null) }
            } catch (e: Exception) {
                main.post { result.error("KEYSTORE", e.javaClass.simpleName, null) }
            }
        }
    }

    companion object {
        private val EXECUTOR = Executors.newSingleThreadExecutor()
    }
}
