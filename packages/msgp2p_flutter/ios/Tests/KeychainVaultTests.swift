import Foundation
import XCTest
@testable import msgp2p_flutter

/// In-memory Keychain. Like the real one, its items outlive the app's files (the reinstall case).
final class FakeKeychain: KeychainAccess {
    var items: [String: Data] = [:]
    var failWith: OSStatus?
    /// Simulates another caller adding the item just before `add`.
    var raceItem: Data?

    func read(service: String, account: String) throws -> Data? {
        if let status = failWith { throw KeyVaultError.from(status: status) }
        return items["\(service)/\(account)"]
    }

    func add(service: String, account: String, data: Data) throws -> Bool {
        if let status = failWith { throw KeyVaultError.from(status: status) }
        if let race = raceItem {
            items["\(service)/\(account)"] = race
            raceItem = nil
        }
        if items["\(service)/\(account)"] != nil { return false }
        items["\(service)/\(account)"] = data
        return true
    }

    func delete(service: String, account: String) throws {
        if let status = failWith { throw KeyVaultError.from(status: status) }
        items["\(service)/\(account)"] = nil
    }
}

final class KeychainVaultTests: XCTestCase {
    private var dir: URL!
    private var keychain: FakeKeychain!
    private var vault: KeychainVault!

    private func seeds(_ fill: UInt8) -> Data {
        var d = Data(repeating: fill, count: 65)
        d[0] = 1
        return d
    }

    override func setUp() {
        dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        keychain = FakeKeychain()
        vault = KeychainVault(keychain: keychain, markerDirectory: dir)
    }

    override func tearDown() {
        try? FileManager.default.removeItem(at: dir)
    }

    func testFirstCallStoresTheCandidateLaterCallsReturnIt() throws {
        let first = try vault.loadOrCreate(name: "default", candidate: seeds(7))
        XCTAssertTrue(first.created)
        XCTAssertEqual(first.seeds, seeds(7))
        let again = try KeychainVault(keychain: keychain, markerDirectory: dir)
            .loadOrCreate(name: "default", candidate: seeds(9))
        XCTAssertFalse(again.created)
        XCTAssertEqual(again.seeds, seeds(7))
    }

    func testAnItemWithoutItsMarkerIsReplacedAfterAReinstall() throws {
        _ = try vault.loadOrCreate(name: "default", candidate: seeds(1))
        try FileManager.default.removeItem(at: dir) // uninstall: app files gone, Keychain item kept
        let after = try vault.loadOrCreate(name: "default", candidate: seeds(2))
        XCTAssertTrue(after.created)
        XCTAssertEqual(after.seeds, seeds(2))
    }

    func testAMarkerWithoutItsItemCreatesANewIdentity() throws {
        _ = try vault.loadOrCreate(name: "default", candidate: seeds(1))
        keychain.items.removeAll() // e.g. a backup restored to another device
        XCTAssertTrue(try vault.loadOrCreate(name: "default", candidate: seeds(2)).created)
    }

    func testAConcurrentCreatorWins() throws {
        keychain.raceItem = seeds(5)
        let loaded = try vault.loadOrCreate(name: "default", candidate: seeds(6))
        XCTAssertFalse(loaded.created)
        XCTAssertEqual(loaded.seeds, seeds(5))
        XCTAssertEqual(try vault.loadOrCreate(name: "default", candidate: seeds(7)).seeds, seeds(5))
    }

    func testEraseThenANewIdentity() throws {
        _ = try vault.loadOrCreate(name: "default", candidate: seeds(1))
        try vault.erase(name: "default")
        XCTAssertTrue(keychain.items.isEmpty)
        XCTAssertTrue(try vault.loadOrCreate(name: "default", candidate: seeds(2)).created)
    }

    func testALockedKeychainIsReportedAsLocked() {
        keychain.failWith = errSecInteractionNotAllowed
        XCTAssertThrowsError(try vault.loadOrCreate(name: "default", candidate: seeds(1))) { error in
            XCTAssertEqual((error as? KeyVaultError)?.code, "LOCKED")
        }
    }

    func testBadNamesAreRefused() {
        for name in ["", "../x", "a/b", String(repeating: "x", count: 65)] {
            XCTAssertThrowsError(try vault.loadOrCreate(name: name, candidate: seeds(1)))
        }
    }
}
