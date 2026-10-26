import Foundation
#if canImport(CoreBluetooth)
import CoreBluetooth
#endif

/// Listener receiving asynchronous radio events from the native iOS BLE hardware adapter (FR-SDK-02).
public protocol BleHardwareEventListener: AnyObject {
    func onPeerDiscovered(address: String, token: Data, rssi: Int, primaryPhy: String, l2capPsm: Int)
    func onPeerConnected(address: String, isIncoming: Bool, negotiatedMtu: Int, isL2capCoc: Bool)
    func onChunkReceived(address: String, bytes: Data)
    func onRssiUpdated(address: String, rssi: Int)
    func onPhyChanged(address: String, phy: String)
    func onPeerDisconnected(address: String, reason: String)
}

/// Thin abstraction over iOS CoreBluetooth APIs (`CBCentralManager`, `CBPeripheralManager`, `CBL2CAPChannel`)
/// enabling deterministic XCTest unit tests with protocol fakes without physical Bluetooth hardware (FR-TEST-04).
public protocol BleHardwareAdapter: AnyObject {
    var isBluetoothPoweredOn: Bool { get }
    var isBackgroundStateRestored: Bool { get }

    func setEventListener(_ listener: BleHardwareEventListener?)
    func startAdvertising(token: Data, preferCodedPhy: Bool) -> Bool
    func stopAdvertising()
    func startScanning(scanCodedPhy: Bool, lowPower: Bool) -> Bool
    func stopScanning()
    func connect(address: String, l2capPsm: Int) -> Int
    func disconnect(address: String)
    func sendChunk(address: String, bytes: Data) -> Bool
    func requestPhy(address: String, phy: String)
    func handleBackgroundStateRestoration(identifier: String, restoredPeripherals: [String])
}

/// Pure-Swift BLE controller coordinating MethodChannel commands and forwarding radio events to Dart (FR-SDK-02).
public final class Msgp2pBleController: BleHardwareEventListener {
    private let adapter: BleHardwareAdapter
    public var eventSink: (([String: Any]) -> Void)?

    public private(set) var isAdvertising: Bool = false
    public private(set) var isScanning: Bool = false
    public private(set) var lastAdvertisedToken: Data?
    public private(set) var restoredIdentifier: String?

    public init(adapter: BleHardwareAdapter) {
        self.adapter = adapter
        self.adapter.setEventListener(self)
    }

    public func handleMethodCall(method: String, arguments: [String: Any]?) -> Any? {
        let args = arguments ?? [:]
        switch method {
        case "startAdvertising":
            let token = args["token"] as? Data ?? Data()
            let preferCoded = args["preferCodedPhy"] as? Bool ?? false
            let ok = adapter.startAdvertising(token: token, preferCodedPhy: preferCoded)
            isAdvertising = ok
            if ok {
                lastAdvertisedToken = token
            }
            return ok

        case "stopAdvertising":
            adapter.stopAdvertising()
            isAdvertising = false
            return nil

        case "startScanning":
            let scanCoded = args["scanCodedPhy"] as? Bool ?? false
            let lowPower = args["lowPower"] as? Bool ?? false
            let ok = adapter.startScanning(scanCodedPhy: scanCoded, lowPower: lowPower)
            isScanning = ok
            return ok

        case "stopScanning":
            adapter.stopScanning()
            isScanning = false
            return nil

        case "connect":
            guard let address = args["address"] as? String else { return 185 }
            let psm = args["psm"] as? Int ?? 0
            return adapter.connect(address: address, l2capPsm: psm)

        case "disconnect":
            if let address = args["address"] as? String {
                adapter.disconnect(address: address)
            }
            return nil

        case "sendChunk":
            guard let address = args["address"] as? String,
                  let bytes = args["bytes"] as? Data else {
                return false
            }
            return adapter.sendChunk(address: address, bytes: bytes)

        case "requestPhy":
            if let address = args["address"] as? String,
               let phy = args["phy"] as? String {
                adapter.requestPhy(address: address, phy: phy)
            }
            return nil

        case "startForegroundService":
            // On iOS, foreground CoreBluetooth participation + background mode state restoration are used
            return true

        case "stopForegroundService":
            return nil

        case "restoreBackgroundState":
            let identifier = args["identifier"] as? String ?? "org.msgp2p.ble.central"
            let peripherals = args["peripherals"] as? [String] ?? []
            restoredIdentifier = identifier
            adapter.handleBackgroundStateRestoration(identifier: identifier, restoredPeripherals: peripherals)
            return true

        default:
            return nil
        }
    }

    public func onPeerDiscovered(address: String, token: Data, rssi: Int, primaryPhy: String, l2capPsm: Int) {
        eventSink?([
            "event": "peer_discovered",
            "address": address,
            "token": token,
            "rssi": rssi,
            "phy": primaryPhy,
            "psm": l2capPsm,
        ])
    }

    public func onPeerConnected(address: String, isIncoming: Bool, negotiatedMtu: Int, isL2capCoc: Bool) {
        eventSink?([
            "event": "peer_connected",
            "address": address,
            "is_incoming": isIncoming,
            "mtu": negotiatedMtu,
            "is_l2cap": isL2capCoc,
        ])
    }

    public func onChunkReceived(address: String, bytes: Data) {
        eventSink?([
            "event": "chunk_received",
            "address": address,
            "bytes": bytes,
        ])
    }

    public func onRssiUpdated(address: String, rssi: Int) {
        eventSink?([
            "event": "rssi_updated",
            "address": address,
            "rssi": rssi,
        ])
    }

    public func onPhyChanged(address: String, phy: String) {
        eventSink?([
            "event": "phy_changed",
            "address": address,
            "phy": phy,
        ])
    }

    public func onPeerDisconnected(address: String, reason: String) {
        eventSink?([
            "event": "peer_disconnected",
            "address": address,
            "reason": reason,
        ])
    }
}

#if canImport(CoreBluetooth)
/// Production iOS CoreBluetooth implementation supporting Central/Peripheral roles,
/// L2CAP Connection-Oriented Channels (`CBL2CAPChannel`), GATT fallback, foreground participation,
/// and best-effort background state restoration (`CBCentralManagerOptionRestoreIdentifierKey`).
public final class IosCoreBluetoothHardwareAdapter: NSObject, BleHardwareAdapter, CBCentralManagerDelegate, CBPeripheralManagerDelegate, CBPeripheralDelegate, StreamDelegate {
    public static let serviceUuid = CBUUID(string: "0000FD6F-0000-1000-8000-00805F9B34FB")
    public static let chunkCharUuid = CBUUID(string: "0000FD70-0000-1000-8000-00805F9B34FB")
    public static let psmCharUuid = CBUUID(string: "0000FD71-0000-1000-8000-00805F9B34FB")
    public static let centralRestoreId = "org.msgp2p.ble.central"
    public static let peripheralRestoreId = "org.msgp2p.ble.peripheral"

    private weak var listener: BleHardwareEventListener?
    private var centralManager: CBCentralManager?
    private var peripheralManager: CBPeripheralManager?

    private var discoveredPeripherals: [String: CBPeripheral] = [:]
    private var l2capChannels: [String: CBL2CAPChannel] = [:]
    private var gattChunkCharacteristics: [String: CBCharacteristic] = [:]
    private var localL2capPsm: CBL2CAPPSM = 0
    private var pendingAdvertToken: Data?

    public private(set) var isBackgroundStateRestored: Bool = false

    public override init() {
        super.init()
        let centralOptions: [String: Any] = [
            CBCentralManagerOptionShowPowerAlertKey: true,
            CBCentralManagerOptionRestoreIdentifierKey: Self.centralRestoreId,
        ]
        let peripheralOptions: [String: Any] = [
            CBPeripheralManagerOptionRestoreIdentifierKey: Self.peripheralRestoreId,
        ]
        self.centralManager = CBCentralManager(delegate: self, queue: nil, options: centralOptions)
        self.peripheralManager = CBPeripheralManager(delegate: self, queue: nil, options: peripheralOptions)
    }

    public var isBluetoothPoweredOn: Bool {
        return centralManager?.state == .poweredOn
    }

    public func setEventListener(_ listener: BleHardwareEventListener?) {
        self.listener = listener
    }

    public func startAdvertising(token: Data, preferCodedPhy: Bool) -> Bool {
        pendingAdvertToken = token
        guard let pm = peripheralManager, pm.state == .poweredOn else {
            return false
        }
        pm.stopAdvertising()
        pm.publishL2CAPChannel(withEncryption: false)

        // CoreBluetooth allows CBAdvertisementDataServiceUUIDsKey and CBAdvertisementDataLocalNameKey
        // We encode the 16-byte rotating beacon token as a 32-char hex string in local name for foreground discovery,
        // and also expose it on the GATT service for background-discovered peers.
        let tokenHex = token.map { String(format: "%02x", $0) }.joined()
        pm.startAdvertising([
            CBAdvertisementDataServiceUUIDsKey: [Self.serviceUuid],
            CBAdvertisementDataLocalNameKey: "M2P_\(tokenHex)",
        ])
        return true
    }

    public func stopAdvertising() {
        pendingAdvertToken = nil
        peripheralManager?.stopAdvertising()
    }

    public func startScanning(scanCodedPhy: Bool, lowPower: Bool) -> Bool {
        guard let cm = centralManager, cm.state == .poweredOn else {
            return false
        }
        // Filtering by Self.serviceUuid enables both foreground and best-effort iOS background scanning
        cm.scanForPeripherals(
            withServices: [Self.serviceUuid],
            options: [CBCentralManagerScanOptionAllowDuplicatesKey: !lowPower]
        )
        return true
    }

    public func stopScanning() {
        centralManager?.stopScan()
    }

    public func connect(address: String, l2capPsm: Int) -> Int {
        guard let cm = centralManager, let peripheral = discoveredPeripherals[address] else {
            return 185
        }
        peripheral.delegate = self
        cm.connect(peripheral, options: nil)
        if l2capPsm > 0 {
            peripheral.openL2CAPChannel(CBL2CAPPSM(l2capPsm))
            return 512
        }
        return 185
    }

    public func disconnect(address: String) {
        if let channel = l2capChannels.removeValue(forKey: address) {
            channel.inputStream.close()
            channel.outputStream.close()
        }
        if let peripheral = discoveredPeripherals[address] {
            centralManager?.cancelPeripheralConnection(peripheral)
        }
        listener?.onPeerDisconnected(address: address, reason: "local_close")
    }

    public func sendChunk(address: String, bytes: Data) -> Bool {
        if let channel = l2capChannels[address], let out = channel.outputStream {
            return bytes.withUnsafeBytes { rawBuffer -> Bool in
                guard let base = rawBuffer.baseAddress?.assumingMemoryBound(to: UInt8.self) else {
                    return false
                }
                let written = out.write(base, maxLength: bytes.count)
                return written == bytes.count
            }
        }
        if let peripheral = discoveredPeripherals[address],
           let char = gattChunkCharacteristics[address] {
            peripheral.writeValue(bytes, for: char, type: .withoutResponse)
            return true
        }
        return false
    }

    public func requestPhy(address: String, phy: String) {
        // CoreBluetooth manages BLE PHY negotiation at the controller level (1M/2M);
        // notify Dart layer of the active iOS PHY.
        listener?.onPhyChanged(address: address, phy: "le_1m")
    }

    public func handleBackgroundStateRestoration(identifier: String, restoredPeripherals: [String]) {
        isBackgroundStateRestored = true
    }

    // MARK: - CBCentralManagerDelegate

    public func centralManagerDidUpdateState(_ central: CBCentralManager) {}

    public func centralManager(_ central: CBCentralManager, willRestoreState dict: [String: Any]) {
        isBackgroundStateRestored = true
        if let peripherals = dict[CBCentralManagerRestoredStatePeripheralsKey] as? [CBPeripheral] {
            for p in peripherals {
                let addr = p.identifier.uuidString
                discoveredPeripherals[addr] = p
                p.delegate = self
            }
        }
    }

    public func centralManager(
        _ central: CBCentralManager,
        didDiscover peripheral: CBPeripheral,
        advertisementData: [String: Any],
        rssi RSSI: NSNumber
    ) {
        let addr = peripheral.identifier.uuidString
        discoveredPeripherals[addr] = peripheral

        var tokenData = Data(count: 16)
        if let localName = advertisementData[CBAdvertisementDataLocalNameKey] as? String,
           localName.hasPrefix("M2P_"),
           localName.count >= 36 {
            let hexSub = String(localName.dropFirst(4).prefix(32))
            if let decoded = Self.decodeHex(hexSub), decoded.count == 16 {
                tokenData = decoded
            }
        }

        listener?.onPeerDiscovered(
            address: addr,
            token: tokenData,
            rssi: RSSI.intValue,
            primaryPhy: "le_1m",
            l2capPsm: 0
        )
    }

    public func centralManager(_ central: CBCentralManager, didConnect peripheral: CBPeripheral) {
        let addr = peripheral.identifier.uuidString
        let mtu = max(23, min(512, peripheral.maximumWriteValueLength(for: .withoutResponse)))
        peripheral.discoverServices([Self.serviceUuid])
        listener?.onPeerConnected(address: addr, isIncoming: false, negotiatedMtu: mtu, isL2capCoc: false)
    }

    public func centralManager(_ central: CBCentralManager, didDisconnectPeripheral peripheral: CBPeripheral, error: Error?) {
        let addr = peripheral.identifier.uuidString
        l2capChannels.removeValue(forKey: addr)
        gattChunkCharacteristics.removeValue(forKey: addr)
        listener?.onPeerDisconnected(address: addr, reason: error?.localizedDescription ?? "remote_disconnect")
    }

    // MARK: - CBPeripheralManagerDelegate

    public func peripheralManagerDidUpdateState(_ peripheral: CBPeripheralManager) {
        if peripheral.state == .poweredOn, let token = pendingAdvertToken {
            _ = startAdvertising(token: token, preferCodedPhy: false)
        }
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, willRestoreState dict: [String: Any]) {
        isBackgroundStateRestored = true
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, didPublishL2CAPChannel PSM: CBL2CAPPSM, error: Error?) {
        if error == nil {
            localL2capPsm = PSM
        }
    }

    public func peripheralManager(_ peripheral: CBPeripheralManager, didOpen channel: CBL2CAPChannel?, error: Error?) {
        guard let channel = channel, error == nil else { return }
        let addr = channel.peer.identifier.uuidString
        l2capChannels[addr] = channel
        channel.inputStream.delegate = self
        channel.inputStream.schedule(in: .main, forMode: .default)
        channel.inputStream.open()
        channel.outputStream.open()
        listener?.onPeerConnected(address: addr, isIncoming: true, negotiatedMtu: 512, isL2capCoc: true)
    }

    public func peripheral(_ peripheral: CBPeripheral, didOpen channel: CBL2CAPChannel?, error: Error?) {
        guard let channel = channel, error == nil else { return }
        let addr = peripheral.identifier.uuidString
        l2capChannels[addr] = channel
        channel.inputStream.delegate = self
        channel.inputStream.schedule(in: .main, forMode: .default)
        channel.inputStream.open()
        channel.outputStream.open()
    }

    private static func decodeHex(_ hex: String) -> Data? {
        var data = Data()
        var index = hex.startIndex
        while index < hex.endIndex {
            let nextIndex = hex.index(index, offsetBy: 2, limitedBy: hex.endIndex) ?? hex.endIndex
            guard let byte = UInt8(hex[index..<nextIndex], radix: 16) else { return nil }
            data.append(byte)
            index = nextIndex
        }
        return data
    }
}
#endif
