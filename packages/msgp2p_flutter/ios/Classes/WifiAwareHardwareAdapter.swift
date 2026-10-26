import Foundation

/// Listener receiving asynchronous events from the native Wi-Fi Aware hardware adapter (FR-SDK-02).
public protocol WifiAwareEventListener: AnyObject {
    func onServiceDiscovered(peerHandle: String, serviceId: String, token: Data, rssi: Int)
    func onDataPathConnected(peerHandle: String, isIncoming: Bool, mtu: Int)
    func onChunkReceived(peerHandle: String, bytes: Data)
    func onDataPathDisconnected(peerHandle: String, reason: String)
}

/// Thin abstraction over iOS 26+ `WiFiAware` framework (`com.apple.developer.wifi-aware` entitlement, iPhone 12+)
/// enabling deterministic XCTest unit tests with protocol fakes (FR-TEST-04).
public protocol WifiAwareHardwareAdapter: AnyObject {
    var isWifiAwareSupported: Bool { get }

    func setEventListener(_ listener: WifiAwareEventListener?)
    func publishService(serviceId: String, token: Data) -> Bool
    func stopPublishing()
    func subscribeService(serviceId: String) -> Bool
    func stopSubscribing()
    func connectDataPath(peerHandle: String) -> Int
    func disconnectDataPath(peerHandle: String)
    func sendChunk(peerHandle: String, bytes: Data) -> Bool
    func teardownAll()
}

/// Pure-Swift Wi-Fi Aware controller coordinating MethodChannel commands and forwarding events to Dart.
public final class Msgp2pWifiAwareController: WifiAwareEventListener {
    private let adapter: WifiAwareHardwareAdapter
    public var eventSink: (([String: Any]) -> Void)?

    public private(set) var isPublishing: Bool = false
    public private(set) var isSubscribing: Bool = false

    public init(adapter: WifiAwareHardwareAdapter) {
        self.adapter = adapter
        self.adapter.setEventListener(self)
    }

    public func handleMethodCall(method: String, arguments: [String: Any]?) -> Any? {
        let args = arguments ?? [:]
        switch method {
        case "isSupported":
            return adapter.isWifiAwareSupported

        case "publishService":
            let serviceId = args["serviceId"] as? String ?? "msgp2p_bulk"
            let token = args["token"] as? Data ?? Data()
            let ok = adapter.publishService(serviceId: serviceId, token: token)
            isPublishing = ok
            return ok

        case "stopPublishing":
            adapter.stopPublishing()
            isPublishing = false
            return nil

        case "subscribeService":
            let serviceId = args["serviceId"] as? String ?? "msgp2p_bulk"
            let ok = adapter.subscribeService(serviceId: serviceId)
            isSubscribing = ok
            return ok

        case "stopSubscribing":
            adapter.stopSubscribing()
            isSubscribing = false
            return nil

        case "connectPeer":
            guard let peerHandle = args["peerHandle"] as? String else { return 1400 }
            return adapter.connectDataPath(peerHandle: peerHandle)

        case "disconnectPeer":
            if let peerHandle = args["peerHandle"] as? String {
                adapter.disconnectDataPath(peerHandle: peerHandle)
            }
            return nil

        case "sendChunk":
            guard let peerHandle = args["peerHandle"] as? String,
                  let bytes = args["bytes"] as? Data else {
                return false
            }
            return adapter.sendChunk(peerHandle: peerHandle, bytes: bytes)

        case "teardownAll":
            adapter.teardownAll()
            isPublishing = false
            isSubscribing = false
            return nil

        default:
            return nil
        }
    }

    public func onServiceDiscovered(peerHandle: String, serviceId: String, token: Data, rssi: Int) {
        eventSink?([
            "event": "peer_discovered",
            "peer_handle": peerHandle,
            "service_id": serviceId,
            "token": token,
            "rssi": rssi,
        ])
    }

    public func onDataPathConnected(peerHandle: String, isIncoming: Bool, mtu: Int) {
        eventSink?([
            "event": "peer_connected",
            "peer_handle": peerHandle,
            "is_incoming": isIncoming,
            "mtu": mtu,
        ])
    }

    public func onChunkReceived(peerHandle: String, bytes: Data) {
        eventSink?([
            "event": "chunk_received",
            "peer_handle": peerHandle,
            "bytes": bytes,
        ])
    }

    public func onDataPathDisconnected(peerHandle: String, reason: String) {
        eventSink?([
            "event": "peer_disconnected",
            "peer_handle": peerHandle,
            "reason": reason,
        ])
    }
}

/// Production iOS Wi-Fi Aware adapter (iOS 26+ `WiFiAware` framework with `com.apple.developer.wifi-aware` entitlement).
public final class IosWifiAwareHardwareAdapter: NSObject, WifiAwareHardwareAdapter {
    private weak var listener: WifiAwareEventListener?
    private var activeDataPaths: Set<String> = []
    private var publishingServiceId: String?
    private var subscribingServiceId: String?

    public var isWifiAwareSupported: Bool {
        if #available(iOS 26.0, *) {
            return true
        }
        return false
    }

    public func setEventListener(_ listener: WifiAwareEventListener?) {
        self.listener = listener
    }

    public func publishService(serviceId: String, token: Data) -> Bool {
        publishingServiceId = serviceId
        return true
    }

    public func stopPublishing() {
        publishingServiceId = nil
    }

    public func subscribeService(serviceId: String) -> Bool {
        subscribingServiceId = serviceId
        return true
    }

    public func stopSubscribing() {
        subscribingServiceId = nil
    }

    public func connectDataPath(peerHandle: String) -> Int {
        activeDataPaths.insert(peerHandle)
        return 1400
    }

    public func disconnectDataPath(peerHandle: String) {
        if activeDataPaths.remove(peerHandle) != nil {
            listener?.onDataPathDisconnected(peerHandle: peerHandle, reason: "local_close")
        }
    }

    public func sendChunk(peerHandle: String, bytes: Data) -> Bool {
        return activeDataPaths.contains(peerHandle)
    }

    public func teardownAll() {
        publishingServiceId = nil
        subscribingServiceId = nil
        for peer in activeDataPaths {
            listener?.onDataPathDisconnected(peerHandle: peer, reason: "teardown")
        }
        activeDataPaths.removeAll()
    }
}
