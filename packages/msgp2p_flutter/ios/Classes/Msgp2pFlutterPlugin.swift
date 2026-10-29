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

        let vault = KeychainVault(keychain: SystemKeychain(), markerDirectory: KeychainVault.defaultMarkerDirectory())
        let keyVaultChannel = FlutterMethodChannel(
            name: "org.msgp2p/key_vault",
            binaryMessenger: registrar.messenger()
        )
        keyVaultChannel.setMethodCallHandler { call, result in
            Msgp2pFlutterPlugin.handleKeyVault(vault, call: call, result: result)
        }
    }

    /// Runs the vault on its serial queue (Keychain calls can block) and replies on the main thread.
    private static func handleKeyVault(_ vault: KeychainVault, call: FlutterMethodCall, result: @escaping FlutterResult) {
        let args = call.arguments as? [String: Any]
        guard let name = args?["name"] as? String, KeychainVault.isValidName(name) else {
            result(FlutterError(code: "BAD_ARGS", message: "missing or bad vault name", details: nil))
            return
        }
        let action: () throws -> Any?
        switch call.method {
        case "loadOrCreate":
            guard let candidate = (args?["candidate"] as? FlutterStandardTypedData)?.data else {
                result(FlutterError(code: "BAD_ARGS", message: "missing candidate", details: nil))
                return
            }
            action = {
                let loaded = try vault.loadOrCreate(name: name, candidate: candidate)
                return ["seeds": FlutterStandardTypedData(bytes: loaded.seeds), "created": loaded.created] as [String: Any]
            }
        case "erase":
            action = {
                try vault.erase(name: name)
                return nil
            }
        default:
            result(FlutterMethodNotImplemented)
            return
        }
        KeychainVault.queue.async {
            let reply: Any?
            do {
                reply = try action()
            } catch let error as KeyVaultError {
                reply = FlutterError(code: error.code, message: error.message, details: nil)
            } catch {
                reply = FlutterError(code: "KEYCHAIN", message: String(describing: type(of: error)), details: nil)
            }
            DispatchQueue.main.async { result(reply) }
        }
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
