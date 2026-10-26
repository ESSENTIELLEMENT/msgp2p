package org.msgp2p.flutter

/**
 * Listener receiving raw radio events from the thin native BLE hardware adapter (FR-SDK-02).
 *
 * Notice: No CBOR parsing, framing, chunk reassembly, or cryptographic handshakes exist in Kotlin.
 */
interface BleRadioEventListener {
    fun onPeerDiscovered(address: String, token: ByteArray, rssi: Int, phy: String, l2capPsm: Int)
    fun onPeerConnected(address: String, isIncoming: Boolean, negotiatedMtu: Int, isL2cap: Boolean)
    fun onChunkReceived(address: String, bytes: ByteArray)
    fun onRssiUpdated(address: String, rssi: Int)
    fun onPhyChanged(address: String, phy: String)
    fun onPeerDisconnected(address: String, reason: String)
}

/**
 * Abstract hardware interface wrapping Android Bluetooth APIs so that controller logic
 * can be unit-tested on a standard JVM without physical radios (FR-TEST-04).
 */
interface BleHardwareAdapter {
    val isExtendedAdvertisingSupported: Boolean
    val isCodedPhySupported: Boolean
    val is2MPhySupported: Boolean

    fun setEventListener(listener: BleRadioEventListener?)
    fun startAdvertising(token: ByteArray, preferCodedPhy: Boolean)
    fun stopAdvertising()
    fun startScanning(scanCodedPhy: Boolean, lowPower: Boolean)
    fun stopScanning()
    fun connect(address: String, l2capPsm: Int): Int
    fun disconnect(address: String)
    fun sendChunk(address: String, bytes: ByteArray)
    fun requestPhy(address: String, phy: String)
}

/**
 * Stateless controller coordinating the thin native BLE adapter and adaptive PHY requests
 * on behalf of the Flutter MethodChannel/EventChannel bridge (`FR-SDK-02`, `FR-SYNC-06`).
 */
class Msgp2pBleController(
    private val hardware: BleHardwareAdapter
) {
    var isAdvertising: Boolean = false
        private set

    var isScanning: Boolean = false
        private set

    var lastAdvertisedToken: ByteArray? = null
        private set

    fun startAdvertising(token: ByteArray, preferCodedPhy: Boolean) {
        require(token.size == 16) { "Rotating BLE beacon token must be 16 bytes (got ${token.size})" }
        val useCoded = preferCodedPhy && hardware.isExtendedAdvertisingSupported && hardware.isCodedPhySupported
        hardware.startAdvertising(token.copyOf(), useCoded)
        lastAdvertisedToken = token.copyOf()
        isAdvertising = true
    }

    fun stopAdvertising() {
        hardware.stopAdvertising()
        isAdvertising = false
    }

    fun startScanning(scanCodedPhy: Boolean, lowPower: Boolean) {
        val useCoded = scanCodedPhy && hardware.isCodedPhySupported
        hardware.startScanning(useCoded, lowPower)
        isScanning = true
    }

    fun stopScanning() {
        hardware.stopScanning()
        isScanning = false
    }

    fun connect(address: String, l2capPsm: Int): Int {
        return hardware.connect(address, l2capPsm)
    }

    fun disconnect(address: String) {
        hardware.disconnect(address)
    }

    fun sendChunk(address: String, bytes: ByteArray) {
        hardware.sendChunk(address, bytes)
    }

    fun requestPhy(address: String, phy: String) {
        val effectivePhy = when (phy) {
            "le_coded_s8" -> if (hardware.isCodedPhySupported) "le_coded_s8" else "le_1m"
            "le_2m" -> if (hardware.is2MPhySupported) "le_2m" else "le_1m"
            else -> "le_1m"
        }
        hardware.requestPhy(address, effectivePhy)
    }
}
