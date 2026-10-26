package org.msgp2p.flutter

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FakeBleHardwareAdapter(
    override val isExtendedAdvertisingSupported: Boolean = true,
    override val isCodedPhySupported: Boolean = true,
    override val is2MPhySupported: Boolean = true
) : BleHardwareAdapter {
    var listener: BleRadioEventListener? = null
    var lastAdvCodedPhy: Boolean = false
    var lastScanCodedPhy: Boolean = false
    var lastRequestedPhy: String? = null
    val sentChunks = mutableListOf<Pair<String, ByteArray>>()

    override fun setEventListener(listener: BleRadioEventListener?) {
        this.listener = listener
    }

    override fun startAdvertising(token: ByteArray, preferCodedPhy: Boolean) {
        lastAdvCodedPhy = preferCodedPhy
    }

    override fun stopAdvertising() {}

    override fun startScanning(scanCodedPhy: Boolean, lowPower: Boolean) {
        lastScanCodedPhy = scanCodedPhy
    }

    override fun stopScanning() {}

    override fun connect(address: String, l2capPsm: Int): Int = 512

    override fun disconnect(address: String) {}

    override fun sendChunk(address: String, bytes: ByteArray) {
        sentChunks.add(address to bytes)
    }

    override fun requestPhy(address: String, phy: String) {
        lastRequestedPhy = phy
        listener?.onPhyChanged(address, phy)
    }
}

class Msgp2pBleControllerTest {
    @Test
    fun `startAdvertising validates 16-byte beacon token and uses Coded PHY when supported`() {
        val fakeHw = FakeBleHardwareAdapter(isExtendedAdvertisingSupported = true, isCodedPhySupported = true)
        val controller = Msgp2pBleController(fakeHw)

        val token = ByteArray(16) { it.toByte() }
        controller.startAdvertising(token, preferCodedPhy = true)

        assertTrue(controller.isAdvertising)
        assertTrue(fakeHw.lastAdvCodedPhy)
        assertArrayEquals(token, controller.lastAdvertisedToken)

        controller.stopAdvertising()
        assertFalse(controller.isAdvertising)
    }

    @Test
    fun `requestPhy falls back to le_1m when device lacks Coded PHY support`() {
        val fakeHw = FakeBleHardwareAdapter(isCodedPhySupported = false, is2MPhySupported = false)
        val controller = Msgp2pBleController(fakeHw)

        controller.requestPhy("AA:BB:CC:DD:EE:01", "le_coded_s8")
        assertEquals("le_1m", fakeHw.lastRequestedPhy)

        controller.requestPhy("AA:BB:CC:DD:EE:01", "le_2m")
        assertEquals("le_1m", fakeHw.lastRequestedPhy)
    }

    @Test
    fun `sendChunk forwards raw byte chunks unmodified without protocol parsing`() {
        val fakeHw = FakeBleHardwareAdapter()
        val controller = Msgp2pBleController(fakeHw)

        val rawChunk = byteArrayOf(0x01, 0x02, 0x03, 0x04)
        controller.sendChunk("AA:BB:CC:DD:EE:02", rawChunk)

        assertEquals(1, fakeHw.sentChunks.size)
        assertEquals("AA:BB:CC:DD:EE:02", fakeHw.sentChunks.first().first)
        assertArrayEquals(rawChunk, fakeHw.sentChunks.first().second)
    }

    @Test
    fun `WifiAwareController publishes, subscribes, sends bulk chunks, and tears down cleanly`() {
        val fakeAware = object : WifiAwareHardwareAdapter {
            override val isWifiAwareSupported: Boolean = true
            var listener: WifiAwareEventListener? = null
            val activePeers = mutableSetOf<String>()
            val sent = mutableListOf<Pair<String, ByteArray>>()

            override fun setEventListener(listener: WifiAwareEventListener?) {
                this.listener = listener
            }

            override fun publishService(serviceId: String, token: ByteArray): Boolean = true
            override fun stopPublishing() {}
            override fun subscribeService(serviceId: String): Boolean = true
            override fun stopSubscribing() {}
            override fun connectDataPath(peerHandle: String): Int {
                activePeers.add(peerHandle)
                return 1400
            }

            override fun disconnectDataPath(peerHandle: String) {
                activePeers.remove(peerHandle)
            }

            override fun sendChunk(peerHandle: String, bytes: ByteArray): Boolean {
                if (!activePeers.contains(peerHandle)) return false
                sent.add(peerHandle to bytes)
                return true
            }

            override fun teardownAll() {
                activePeers.clear()
            }
        }

        val controller = Msgp2pWifiAwareController(fakeAware)
        val token = ByteArray(16) { (it + 1).toByte() }
        assertTrue(controller.publishService("msgp2p_bulk", token))
        assertTrue(controller.isPublishing)
        assertArrayEquals(token, controller.lastPublishedToken)

        assertTrue(controller.subscribeService("msgp2p_bulk"))
        assertTrue(controller.isSubscribing)

        val mtu = controller.connectPeer("NAN-PEER-01")
        assertEquals(1400, mtu)

        val bulkChunk = ByteArray(1200) { 0x42 }
        assertTrue(controller.sendChunk("NAN-PEER-01", bulkChunk))
        assertEquals(1, fakeAware.sent.size)

        controller.teardownAll()
        assertFalse(controller.isPublishing)
        assertFalse(controller.isSubscribing)
        assertTrue(fakeAware.activePeers.isEmpty())
    }
}
