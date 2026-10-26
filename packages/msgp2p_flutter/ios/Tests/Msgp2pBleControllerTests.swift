import Foundation
import XCTest
@testable import msgp2p_flutter

/// Fake CoreBluetooth hardware adapter for deterministic XCTest unit tests (FR-TEST-04).
final class FakeBleHardwareAdapter: BleHardwareAdapter {
    var isBluetoothPoweredOn: Bool = true
    var isBackgroundStateRestored: Bool = false

    weak var listener: BleHardwareEventListener?
    var advertisingStarted: Bool = false
    var scanningStarted: Bool = false
    var advertisedToken: Data?
    var connectedPeers: [String: Int] = [:]
    var sentChunks: [(address: String, bytes: Data)] = []
    var requestedPhys: [String: String] = [:]
    var restoredPeripherals: [String] = []

    func setEventListener(_ listener: BleHardwareEventListener?) {
        self.listener = listener
    }

    func startAdvertising(token: Data, preferCodedPhy: Bool) -> Bool {
        guard isBluetoothPoweredOn else { return false }
        advertisingStarted = true
        advertisedToken = token
        return true
    }

    func stopAdvertising() {
        advertisingStarted = false
    }

    func startScanning(scanCodedPhy: Bool, lowPower: Bool) -> Bool {
        guard isBluetoothPoweredOn else { return false }
        scanningStarted = true
        return true
    }

    func stopScanning() {
        scanningStarted = false
    }

    func connect(address: String, l2capPsm: Int) -> Int {
        let mtu = l2capPsm > 0 ? 512 : 185
        connectedPeers[address] = mtu
        return mtu
    }

    func disconnect(address: String) {
        connectedPeers.removeValue(forKey: address)
        listener?.onPeerDisconnected(address: address, reason: "local_close")
    }

    func sendChunk(address: String, bytes: Data) -> Bool {
        guard connectedPeers[address] != nil else { return false }
        sentChunks.append((address: address, bytes: bytes))
        return true
    }

    func requestPhy(address: String, phy: String) {
        requestedPhys[address] = phy
        listener?.onPhyChanged(address: address, phy: "le_1m")
    }

    func handleBackgroundStateRestoration(identifier: String, restoredPeripherals: [String]) {
        isBackgroundStateRestored = true
        self.restoredPeripherals = restoredPeripherals
    }
}

/// Fake Wi-Fi Aware hardware adapter for deterministic XCTest unit tests (FR-TEST-04).
final class FakeWifiAwareHardwareAdapter: WifiAwareHardwareAdapter {
    var isWifiAwareSupported: Bool = true
    weak var listener: WifiAwareEventListener?

    var publishedServiceId: String?
    var publishedToken: Data?
    var subscribedServiceId: String?
    var connectedPeers: Set<String> = []
    var sentChunks: [(peerHandle: String, bytes: Data)] = []

    func setEventListener(_ listener: WifiAwareEventListener?) {
        self.listener = listener
    }

    func publishService(serviceId: String, token: Data) -> Bool {
        publishedServiceId = serviceId
        publishedToken = token
        return true
    }

    func stopPublishing() {
        publishedServiceId = nil
    }

    func subscribeService(serviceId: String) -> Bool {
        subscribedServiceId = serviceId
        return true
    }

    func stopSubscribing() {
        subscribedServiceId = nil
    }

    func connectDataPath(peerHandle: String) -> Int {
        connectedPeers.insert(peerHandle)
        return 1400
    }

    func disconnectDataPath(peerHandle: String) {
        connectedPeers.remove(peerHandle)
        listener?.onDataPathDisconnected(peerHandle: peerHandle, reason: "local_close")
    }

    func sendChunk(peerHandle: String, bytes: Data) -> Bool {
        guard connectedPeers.contains(peerHandle) else { return false }
        sentChunks.append((peerHandle: peerHandle, bytes: bytes))
        return true
    }

    func teardownAll() {
        publishedServiceId = nil
        subscribedServiceId = nil
        for peer in connectedPeers {
            listener?.onDataPathDisconnected(peerHandle: peer, reason: "teardown")
        }
        connectedPeers.removeAll()
    }
}

final class Msgp2pBleControllerTests: XCTestCase {
    func testForegroundAdvertisingAndScanning() {
        let fake = FakeBleHardwareAdapter()
        let controller = Msgp2pBleController(adapter: fake)
        var emittedEvents: [[String: Any]] = []
        controller.eventSink = { event in
            emittedEvents.append(event)
        }

        let token = Data(repeating: 0xAB, count: 16)
        let advOk = controller.handleMethodCall(
            method: "startAdvertising",
            arguments: ["token": token, "preferCodedPhy": false]
        ) as? Bool
        XCTAssertEqual(advOk, true)
        XCTAssertTrue(controller.isAdvertising)
        XCTAssertEqual(fake.advertisedToken, token)

        let scanOk = controller.handleMethodCall(
            method: "startScanning",
            arguments: ["scanCodedPhy": false, "lowPower": false]
        ) as? Bool
        XCTAssertEqual(scanOk, true)
        XCTAssertTrue(controller.isScanning)

        fake.listener?.onPeerDiscovered(
            address: "CB-PEER-UUID-1",
            token: token,
            rssi: -64,
            primaryPhy: "le_1m",
            l2capPsm: 128
        )
        XCTAssertEqual(emittedEvents.count, 1)
        XCTAssertEqual(emittedEvents[0]["event"] as? String, "peer_discovered")
        XCTAssertEqual(emittedEvents[0]["address"] as? String, "CB-PEER-UUID-1")
    }

    func testL2capAndGattFallbackConnectionAndChunks() {
        let fake = FakeBleHardwareAdapter()
        let controller = Msgp2pBleController(adapter: fake)
        var emittedEvents: [[String: Any]] = []
        controller.eventSink = { event in
            emittedEvents.append(event)
        }

        // L2CAP CoC connection (PSM > 0 -> MTU 512)
        let l2capMtu = controller.handleMethodCall(
            method: "connect",
            arguments: ["address": "CB-PEER-1", "psm": 128]
        ) as? Int
        XCTAssertEqual(l2capMtu, 512)

        // GATT fallback connection (PSM == 0 -> MTU 185)
        let gattMtu = controller.handleMethodCall(
            method: "connect",
            arguments: ["address": "CB-PEER-2", "psm": 0]
        ) as? Int
        XCTAssertEqual(gattMtu, 185)

        let payload = Data([0x01, 0x02, 0x03, 0x04])
        let sent = controller.handleMethodCall(
            method: "sendChunk",
            arguments: ["address": "CB-PEER-1", "bytes": payload]
        ) as? Bool
        XCTAssertEqual(sent, true)
        XCTAssertEqual(fake.sentChunks.count, 1)

        fake.listener?.onChunkReceived(address: "CB-PEER-1", bytes: payload)
        XCTAssertEqual(emittedEvents.last?["event"] as? String, "chunk_received")
    }

    func testBackgroundStateRestorationBestEffort() {
        let fake = FakeBleHardwareAdapter()
        let controller = Msgp2pBleController(adapter: fake)

        let restored = controller.handleMethodCall(
            method: "restoreBackgroundState",
            arguments: [
                "identifier": "org.msgp2p.ble.central",
                "peripherals": ["CB-RESTORED-1", "CB-RESTORED-2"]
            ]
        ) as? Bool
        XCTAssertEqual(restored, true)
        XCTAssertTrue(fake.isBackgroundStateRestored)
        XCTAssertEqual(fake.restoredPeripherals.count, 2)
    }

    func testWifiAwarePublishSubscribeConnectAndTeardown() {
        let fake = FakeWifiAwareHardwareAdapter()
        let controller = Msgp2pWifiAwareController(adapter: fake)
        var emittedEvents: [[String: Any]] = []
        controller.eventSink = { event in
            emittedEvents.append(event)
        }

        let token = Data(repeating: 0xCD, count: 16)
        _ = controller.handleMethodCall(
            method: "publishService",
            arguments: ["serviceId": "msgp2p_bulk", "token": token]
        )
        XCTAssertTrue(controller.isPublishing)

        _ = controller.handleMethodCall(
            method: "subscribeService",
            arguments: ["serviceId": "msgp2p_bulk"]
        )
        XCTAssertTrue(controller.isSubscribing)

        let mtu = controller.handleMethodCall(
            method: "connectPeer",
            arguments: ["peerHandle": "NAN-PEER-01"]
        ) as? Int
        XCTAssertEqual(mtu, 1400)

        let chunk = Data(repeating: 0x55, count: 1024)
        let sent = controller.handleMethodCall(
            method: "sendChunk",
            arguments: ["peerHandle": "NAN-PEER-01", "bytes": chunk]
        ) as? Bool
        XCTAssertEqual(sent, true)

        _ = controller.handleMethodCall(method: "teardownAll", arguments: nil)
        XCTAssertFalse(controller.isPublishing)
        XCTAssertFalse(controller.isSubscribing)
        XCTAssertTrue(fake.connectedPeers.isEmpty)
        XCTAssertEqual(emittedEvents.last?["event"] as? String, "peer_disconnected")
    }
}
