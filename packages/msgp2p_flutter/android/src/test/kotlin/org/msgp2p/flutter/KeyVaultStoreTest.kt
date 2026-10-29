package org.msgp2p.flutter

import java.io.File
import java.nio.file.Files
import java.util.concurrent.Callable
import java.util.concurrent.Executors
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import org.junit.After
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test

/** Software AES keys standing in for the Android Keystore (the format and flow are what is tested). */
class FakeSealingKeys : SealingKeys {
    val keys = mutableMapOf<String, SecretKey>()

    override fun get(alias: String): SecretKey? = synchronized(keys) { keys[alias] }

    override fun create(alias: String): SecretKey = synchronized(keys) {
        val key = KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
        keys[alias] = key
        key
    }

    override fun delete(alias: String) {
        synchronized(keys) { keys.remove(alias) }
    }
}

class KeyVaultStoreTest {
    private val dir: File = Files.createTempDirectory("keyvault").toFile()
    private val keys = FakeSealingKeys()
    private val store = KeyVaultStore(dir, keys)

    private fun seeds(fill: Int) = ByteArray(65) { fill.toByte() }.also { it[0] = 1 }

    private fun expectCode(code: String, action: () -> Unit) {
        try {
            action()
            fail("expected $code")
        } catch (e: KeyVaultException) {
            assertEquals(code, e.code)
        }
    }

    @After
    fun cleanUp() {
        dir.deleteRecursively()
    }

    @Test
    fun firstCallStoresTheCandidateLaterCallsReturnIt() {
        val (first, created) = store.loadOrCreate("default", seeds(7))
        assertTrue(created)
        assertArrayEquals(seeds(7), first)
        val (again, createdAgain) = KeyVaultStore(dir, keys).loadOrCreate("default", seeds(9))
        assertFalse(createdAgain)
        assertArrayEquals(seeds(7), again)
        assertFalse("seeds are not stored in plain text", File(dir, "keyvault-default.bin").readBytes()
            .toList().windowed(32).any { it.all { b -> b == 7.toByte() } })
    }

    @Test
    fun namesAreSeparateIdentities() {
        store.loadOrCreate("a", seeds(1))
        assertArrayEquals(seeds(2), store.loadOrCreate("b", seeds(2)).first)
        assertArrayEquals(seeds(1), store.loadOrCreate("a", seeds(3)).first)
    }

    @Test
    fun eraseThenANewIdentity() {
        store.loadOrCreate("default", seeds(1))
        store.erase("default")
        assertTrue(keys.keys.isEmpty())
        val (after, created) = store.loadOrCreate("default", seeds(2))
        assertTrue(created)
        assertArrayEquals(seeds(2), after)
    }

    @Test
    fun aFileWithoutItsKeyIsUnavailable() {
        store.loadOrCreate("default", seeds(1))
        keys.keys.clear() // as on another device after a restored backup
        expectCode("UNAVAILABLE") { store.loadOrCreate("default", seeds(2)) }
        store.erase("default")
        assertTrue(store.loadOrCreate("default", seeds(2)).second)
    }

    @Test
    fun aFileSealedByAnotherKeyIsUnavailable() {
        store.loadOrCreate("default", seeds(1))
        keys.create("org.msgp2p.keyvault.default")
        expectCode("UNAVAILABLE") { store.loadOrCreate("default", seeds(2)) }
    }

    @Test
    fun aMalformedFileIsCorruptedAndKept() {
        dir.mkdirs()
        val file = File(dir, "keyvault-default.bin").apply { writeBytes(byteArrayOf(1, 2, 3)) }
        expectCode("CORRUPTED") { store.loadOrCreate("default", seeds(2)) }
        assertArrayEquals(byteArrayOf(1, 2, 3), file.readBytes())
    }

    @Test
    fun aLeftoverKeyWithoutAFileIsReplaced() {
        val stale = keys.create("org.msgp2p.keyvault.default")
        assertTrue(store.loadOrCreate("default", seeds(1)).second)
        assertFalse(keys.keys["org.msgp2p.keyvault.default"] === stale)
    }

    @Test
    fun concurrentFirstCallsCreateOneIdentity() {
        val pool = Executors.newFixedThreadPool(8)
        val results = (1..16).map { i ->
            pool.submit(Callable { KeyVaultStore(dir, keys).loadOrCreate("default", seeds(i)) })
        }.map { it.get() }
        pool.shutdown()
        assertEquals(1, results.count { it.second })
        results.forEach { assertArrayEquals(results.first().first, it.first) }
    }

    @Test
    fun badNamesAreRefused() {
        for (name in listOf("", "../x", "a/b", "x".repeat(65))) {
            try {
                store.loadOrCreate(name, seeds(1))
                fail("accepted '$name'")
            } catch (e: IllegalArgumentException) {
                // expected
            }
        }
    }
}
