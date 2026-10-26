package org.msgp2p.flutter

import android.content.Context
import android.content.Intent
import android.os.Build
import io.flutter.embedding.engine.plugins.FlutterPlugin
import io.flutter.plugin.common.EventChannel
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel

/**
 * Thin Flutter plugin entry point wiring `org.msgp2p/ble_commands` and `org.msgp2p/ble_events`
 * to [Msgp2pBleController] and [Msgp2pForegroundService] (FR-SDK-02).
 */
class Msgp2pFlutterPlugin : FlutterPlugin, MethodChannel.MethodCallHandler, EventChannel.StreamHandler {
    private lateinit var methodChannel: MethodChannel
    private lateinit var eventChannel: EventChannel
    private lateinit var wifiAwareMethodChannel: MethodChannel
    private lateinit var wifiAwareEventChannel: EventChannel
    private var applicationContext: Context? = null
    private var eventSink: EventChannel.EventSink? = null
    private var wifiAwareController: Msgp2pWifiAwareController? = null

    override fun onAttachedToEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        val ctx = binding.applicationContext
        applicationContext = ctx
        methodChannel = MethodChannel(binding.binaryMessenger, "org.msgp2p/ble_commands")
        methodChannel.setMethodCallHandler(this)

        eventChannel = EventChannel(binding.binaryMessenger, "org.msgp2p/ble_events")
        eventChannel.setStreamHandler(this)

        val awareHw = AndroidWifiAwareHardwareAdapter(ctx)
        wifiAwareController = Msgp2pWifiAwareController(awareHw)
        wifiAwareMethodChannel = MethodChannel(binding.binaryMessenger, "org.msgp2p/wifi_aware_commands")
        wifiAwareMethodChannel.setMethodCallHandler { call, result ->
            val ctrl = wifiAwareController
            if (ctrl == null) {
                result.error("UNAVAILABLE", "Wi-Fi Aware controller not initialized", null)
                return@setMethodCallHandler
            }
            when (call.method) {
                "isSupported" -> result.success(ctrl.isSupported())
                "publishService" -> {
                    val serviceId = call.argument<String>("serviceId") ?: "msgp2p_bulk"
                    val token = call.argument<ByteArray>("token") ?: ByteArray(0)
                    result.success(ctrl.publishService(serviceId, token))
                }
                "stopPublishing" -> {
                    ctrl.stopPublishing()
                    result.success(null)
                }
                "subscribeService" -> {
                    val serviceId = call.argument<String>("serviceId") ?: "msgp2p_bulk"
                    result.success(ctrl.subscribeService(serviceId))
                }
                "stopSubscribing" -> {
                    ctrl.stopSubscribing()
                    result.success(null)
                }
                "connectPeer" -> {
                    val peerHandle = call.argument<String>("peerHandle") ?: ""
                    result.success(ctrl.connectPeer(peerHandle))
                }
                "disconnectPeer" -> {
                    val peerHandle = call.argument<String>("peerHandle") ?: ""
                    ctrl.disconnectPeer(peerHandle)
                    result.success(null)
                }
                "sendChunk" -> {
                    val peerHandle = call.argument<String>("peerHandle") ?: ""
                    val bytes = call.argument<ByteArray>("bytes") ?: ByteArray(0)
                    result.success(ctrl.sendChunk(peerHandle, bytes))
                }
                "teardownAll" -> {
                    ctrl.teardownAll()
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        }
        wifiAwareEventChannel = EventChannel(binding.binaryMessenger, "org.msgp2p/wifi_aware_events")
    }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "startForegroundService" -> {
                val ctx = applicationContext
                if (ctx != null) {
                    val intent = Intent(ctx, Msgp2pForegroundService::class.java).apply {
                        putExtra(Msgp2pForegroundService.EXTRA_TITLE, call.argument<String>("title"))
                        putExtra(Msgp2pForegroundService.EXTRA_CONTENT, call.argument<String>("content"))
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                        ctx.startForegroundService(intent)
                    } else {
                        ctx.startService(intent)
                    }
                }
                result.success(true)
            }
            "stopForegroundService" -> {
                val ctx = applicationContext
                if (ctx != null) {
                    ctx.stopService(Intent(ctx, Msgp2pForegroundService::class.java))
                }
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    override fun onListen(arguments: Any?, events: EventChannel.EventSink?) {
        eventSink = events
    }

    override fun onCancel(arguments: Any?) {
        eventSink = null
    }

    override fun onDetachedFromEngine(binding: FlutterPlugin.FlutterPluginBinding) {
        methodChannel.setMethodCallHandler(null)
        eventChannel.setStreamHandler(null)
        wifiAwareMethodChannel.setMethodCallHandler(null)
        wifiAwareController?.teardownAll()
        wifiAwareController = null
        applicationContext = null
    }
}
