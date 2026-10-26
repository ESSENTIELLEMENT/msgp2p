package org.msgp2p.flutter

import android.annotation.SuppressLint
import android.content.Context
import android.content.pm.PackageManager
import android.net.wifi.aware.AttachCallback
import android.net.wifi.aware.DiscoverySessionCallback
import android.net.wifi.aware.PeerHandle
import android.net.wifi.aware.PublishConfig
import android.net.wifi.aware.PublishDiscoverySession
import android.net.wifi.aware.SubscribeConfig
import android.net.wifi.aware.SubscribeDiscoverySession
import android.net.wifi.aware.WifiAwareManager
import android.net.wifi.aware.WifiAwareSession
import android.os.Build

/**
 * Listener receiving asynchronous events from the native Android Wi-Fi Aware (NAN) adapter (FR-SDK-02).
 */
interface WifiAwareEventListener {
    fun onServiceDiscovered(peerHandle: String, serviceId: String, token: ByteArray, rssi: Int)
    fun onDataPathConnected(peerHandle: String, isIncoming: Boolean, mtu: Int)
    fun onChunkReceived(peerHandle: String, bytes: ByteArray)
    fun onDataPathDisconnected(peerHandle: String, reason: String)
}

/**
 * Thin hardware abstraction over Android `WifiAwareManager` (API 26+) enabling
 * deterministic JUnit tests without physical NAN radio hardware (FR-TEST-04).
 */
interface WifiAwareHardwareAdapter {
    val isWifiAwareSupported: Boolean

    fun setEventListener(listener: WifiAwareEventListener?)
    fun publishService(serviceId: String, token: ByteArray): Boolean
    fun stopPublishing()
    fun subscribeService(serviceId: String): Boolean
    fun stopSubscribing()
    fun connectDataPath(peerHandle: String): Int
    fun disconnectDataPath(peerHandle: String)
    fun sendChunk(peerHandle: String, bytes: ByteArray): Boolean
    fun teardownAll()
}

/**
 * Pure-Kotlin Wi-Fi Aware controller testable on JVM (FR-TEST-04).
 */
class Msgp2pWifiAwareController(private val hardware: WifiAwareHardwareAdapter) {
    var isPublishing: Boolean = false
        private set
    var isSubscribing: Boolean = false
        private set
    var lastPublishedToken: ByteArray? = null
        private set

    fun isSupported(): Boolean = hardware.isWifiAwareSupported

    fun publishService(serviceId: String, token: ByteArray): Boolean {
        if (!hardware.isWifiAwareSupported) return false
        val ok = hardware.publishService(serviceId, token)
        isPublishing = ok
        if (ok) {
            lastPublishedToken = token.copyOf()
        }
        return ok
    }

    fun stopPublishing() {
        hardware.stopPublishing()
        isPublishing = false
    }

    fun subscribeService(serviceId: String): Boolean {
        if (!hardware.isWifiAwareSupported) return false
        val ok = hardware.subscribeService(serviceId)
        isSubscribing = ok
        return ok
    }

    fun stopSubscribing() {
        hardware.stopSubscribing()
        isSubscribing = false
    }

    fun connectPeer(peerHandle: String): Int {
        return hardware.connectDataPath(peerHandle)
    }

    fun disconnectPeer(peerHandle: String) {
        hardware.disconnectDataPath(peerHandle)
    }

    fun sendChunk(peerHandle: String, bytes: ByteArray): Boolean {
        return hardware.sendChunk(peerHandle, bytes)
    }

    fun teardownAll() {
        hardware.teardownAll()
        isPublishing = false
        isSubscribing = false
    }
}

/**
 * Production Android `WifiAwareManager` implementation (Android 8.0+ / API 26+).
 */
@SuppressLint("MissingPermission")
class AndroidWifiAwareHardwareAdapter(private val context: Context) : WifiAwareHardwareAdapter {
    private val awareManager: WifiAwareManager? =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.getSystemService(Context.WIFI_AWARE_SERVICE) as? WifiAwareManager
        } else null

    private var eventListener: WifiAwareEventListener? = null
    private var awareSession: WifiAwareSession? = null
    private var publishSession: PublishDiscoverySession? = null
    private var subscribeSession: SubscribeDiscoverySession? = null
    private val discoveredPeers = mutableMapOf<String, PeerHandle>()
    private val activeConnections = mutableSetOf<String>()

    override val isWifiAwareSupported: Boolean
        get() = Build.VERSION.SDK_INT >= Build.VERSION_CODES.O &&
                context.packageManager.hasSystemFeature(PackageManager.FEATURE_WIFI_AWARE) &&
                (awareManager?.isAvailable == true)

    override fun setEventListener(listener: WifiAwareEventListener?) {
        eventListener = listener
    }

    private fun ensureAttached(onAttached: (WifiAwareSession) -> Unit) {
        val existing = awareSession
        if (existing != null) {
            onAttached(existing)
            return
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            awareManager?.attach(object : AttachCallback() {
                override fun onAttached(session: WifiAwareSession) {
                    awareSession = session
                    onAttached(session)
                }
            }, null)
        }
    }

    override fun publishService(serviceId: String, token: ByteArray): Boolean {
        if (!isWifiAwareSupported) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ensureAttached { session ->
                val config = PublishConfig.Builder()
                    .setServiceName(serviceId)
                    .setServiceSpecificInfo(token)
                    .build()
                session.publish(config, object : DiscoverySessionCallback() {
                    override fun onPublishStarted(session: PublishDiscoverySession) {
                        publishSession = session
                    }

                    override fun onMessageReceived(peerHandle: PeerHandle, message: ByteArray) {
                        val id = "NAN-${peerHandle.hashCode()}"
                        discoveredPeers[id] = peerHandle
                        if (!activeConnections.contains(id)) {
                            activeConnections.add(id)
                            eventListener?.onDataPathConnected(id, true, 1400)
                        }
                        eventListener?.onChunkReceived(id, message)
                    }
                }, null)
            }
        }
        return true
    }

    override fun stopPublishing() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            publishSession?.close()
            publishSession = null
        }
    }

    override fun subscribeService(serviceId: String): Boolean {
        if (!isWifiAwareSupported) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            ensureAttached { session ->
                val config = SubscribeConfig.Builder()
                    .setServiceName(serviceId)
                    .build()
                session.subscribe(config, object : DiscoverySessionCallback() {
                    override fun onSubscribeStarted(session: SubscribeDiscoverySession) {
                        subscribeSession = session
                    }

                    override fun onServiceDiscovered(
                        peerHandle: PeerHandle,
                        serviceSpecificInfo: ByteArray?,
                        matchFilter: MutableList<ByteArray>?
                    ) {
                        val id = "NAN-${peerHandle.hashCode()}"
                        discoveredPeers[id] = peerHandle
                        eventListener?.onServiceDiscovered(
                            id,
                            serviceId,
                            serviceSpecificInfo ?: ByteArray(0),
                            -55
                        )
                    }

                    override fun onMessageReceived(peerHandle: PeerHandle, message: ByteArray) {
                        val id = "NAN-${peerHandle.hashCode()}"
                        discoveredPeers[id] = peerHandle
                        eventListener?.onChunkReceived(id, message)
                    }
                }, null)
            }
        }
        return true
    }

    override fun stopSubscribing() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            subscribeSession?.close()
            subscribeSession = null
        }
    }

    override fun connectDataPath(peerHandle: String): Int {
        activeConnections.add(peerHandle)
        return 1400
    }

    override fun disconnectDataPath(peerHandle: String) {
        if (activeConnections.remove(peerHandle)) {
            eventListener?.onDataPathDisconnected(peerHandle, "local_close")
        }
    }

    override fun sendChunk(peerHandle: String, bytes: ByteArray): Boolean {
        if (!activeConnections.contains(peerHandle)) return false
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val handle = discoveredPeers[peerHandle] ?: return false
            val session = subscribeSession ?: publishSession ?: return false
            session.sendMessage(handle, 1, bytes)
            return true
        }
        return false
    }

    override fun teardownAll() {
        stopPublishing()
        stopSubscribing()
        for (peer in activeConnections.toList()) {
            eventListener?.onDataPathDisconnected(peer, "teardown")
        }
        activeConnections.clear()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            awareSession?.close()
            awareSession = null
        }
    }
}
