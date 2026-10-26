#if canImport(Flutter)
import Flutter
import UIKit

public class Msgp2pFlutterPlugin: NSObject, FlutterPlugin {
    private var bleController: Msgp2pBleController?
    private var wifiAwareController: Msgp2pWifiAwareController?

    public static func register(with registrar: FlutterPluginRegistrar) {
        let instance = Msgp2pFlutterPlugin()

        let bleAdapter = IosCoreBluetoothHardwareAdapter()
        let bleCtrl = Msgp2pBleController(adapter: bleAdapter)
        instance.bleController = bleCtrl

        let bleMethodChannel = FlutterMethodChannel(
            name: "org.msgp2p/ble_commands",
            binaryMessenger: registrar.messenger()
        )
        bleMethodChannel.setMethodCallHandler { call, result in
            let args = call.arguments as? [String: Any]
            let res = bleCtrl.handleMethodCall(method: call.method, arguments: args)
            result(res)
        }

        let bleEventChannel = FlutterEventChannel(
            name: "org.msgp2p/ble_events",
            binaryMessenger: registrar.messenger()
        )
        bleEventChannel.setStreamHandler(ChannelStreamHandler { sink in
            bleCtrl.eventSink = sink
        })

        let awareAdapter = IosWifiAwareHardwareAdapter()
        let awareCtrl = Msgp2pWifiAwareController(adapter: awareAdapter)
        instance.wifiAwareController = awareCtrl

        let awareMethodChannel = FlutterMethodChannel(
            name: "org.msgp2p/wifi_aware_commands",
            binaryMessenger: registrar.messenger()
        )
        awareMethodChannel.setMethodCallHandler { call, result in
            let args = call.arguments as? [String: Any]
            let res = awareCtrl.handleMethodCall(method: call.method, arguments: args)
            result(res)
        }

        let awareEventChannel = FlutterEventChannel(
            name: "org.msgp2p/wifi_aware_events",
            binaryMessenger: registrar.messenger()
        )
        awareEventChannel.setStreamHandler(ChannelStreamHandler { sink in
            awareCtrl.eventSink = sink
        })
    }
}

private final class ChannelStreamHandler: NSObject, FlutterStreamHandler {
    private let onSinkChanged: (([String: Any]) -> Void)? -> Void

    init(onSinkChanged: @escaping ((([String: Any]) -> Void)?) -> Void) {
        self.onSinkChanged = onSinkChanged
    }

    func onListen(withArguments arguments: Any?, eventSink events: @escaping FlutterEventSink) -> FlutterError? {
        onSinkChanged { map in
            events(map)
        }
        return nil
    }

    func onCancel(withArguments arguments: Any?) -> FlutterError? {
        onSinkChanged(nil)
        return nil
    }
}
#endif
