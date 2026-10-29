import Foundation
import Security

/// Keychain operations behind a protocol, so XCTest can use a fake.
protocol KeychainAccess {
    /// The item's data, or nil if there is no item.
    func read(service: String, account: String) throws -> Data?
    /// Adds the item; false if one already exists (`errSecDuplicateItem`).
    func add(service: String, account: String, data: Data) throws -> Bool
    /// Deletes the item; no error if there is none.
    func delete(service: String, account: String) throws
}

/// An error with a channel code the Dart `PlatformKeyVault` understands.
struct KeyVaultError: Error {
    let code: String
    let message: String

    static func from(status: OSStatus) -> KeyVaultError {
        if status == errSecInteractionNotAllowed {
            // Before the first unlock after a restart: retry later, do not erase.
            return KeyVaultError(code: "LOCKED", message: "the Keychain is locked until the first unlock")
        }
        return KeyVaultError(code: "KEYCHAIN", message: "Keychain error \(status)")
    }
}

final class SystemKeychain: KeychainAccess {
    private func query(_ service: String, _ account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    func read(service: String, account: String) throws -> Data? {
        var q = query(service, account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess else { throw KeyVaultError.from(status: status) }
        guard let data = item as? Data else {
            throw KeyVaultError(code: "CORRUPTED", message: "the Keychain item has no data")
        }
        return data
    }

    func add(service: String, account: String, data: Data) throws -> Bool {
        var q = query(service, account)
        q[kSecValueData as String] = data
        // Never in backups, never on another device, readable in the background after the first unlock.
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        if status == errSecDuplicateItem { return false }
        guard status == errSecSuccess else { throw KeyVaultError.from(status: status) }
        return true
    }

    func delete(service: String, account: String) throws {
        let status = SecItemDelete(query(service, account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeyVaultError.from(status: status)
        }
    }
}

/// The device identity seeds in the Keychain (proposal 0001, step 2b; Discussion #10), as opaque bytes.
///
/// Keychain items survive uninstalling the app, but Application Support does not. So the vault keeps a marker
/// file there: an item without its marker is left over from an earlier install (whose message store is gone)
/// and is replaced by a new identity. The marker is written only after the item, before the seeds are returned.
/// All calls run on one serial queue, so concurrent first calls (several isolates) create one identity.
final class KeychainVault {
    static let service = "org.msgp2p.keyvault"
    static let queue = DispatchQueue(label: "org.msgp2p.keyvault")

    private let keychain: KeychainAccess
    private let markerDirectory: URL

    init(keychain: KeychainAccess, markerDirectory: URL) {
        self.keychain = keychain
        self.markerDirectory = markerDirectory
    }

    static func defaultMarkerDirectory() -> URL {
        FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("msgp2p", isDirectory: true)
    }

    static func isValidName(_ name: String) -> Bool {
        name.range(of: "^[A-Za-z0-9_-]{1,64}$", options: .regularExpression) != nil
    }

    /// The stored seeds and false, or else [candidate] (now stored) and true.
    func loadOrCreate(name: String, candidate: Data) throws -> (seeds: Data, created: Bool) {
        let marker = try markerURL(name)
        let hasMarker = FileManager.default.fileExists(atPath: marker.path)
        if hasMarker, let stored = try keychain.read(service: Self.service, account: name) {
            return (stored, false)
        }
        if !hasMarker {
            try keychain.delete(service: Self.service, account: name) // left over from an earlier install
        }
        if try keychain.add(service: Self.service, account: name, data: candidate) {
            try writeMarker(marker)
            return (candidate, true)
        }
        // Created by another caller in between.
        guard let stored = try keychain.read(service: Self.service, account: name) else {
            throw KeyVaultError(code: "KEYCHAIN", message: "the Keychain item vanished")
        }
        try writeMarker(marker)
        return (stored, false)
    }

    /// The item first: a marker left without its item only means the next call creates a new identity.
    func erase(name: String) throws {
        let marker = try markerURL(name)
        try keychain.delete(service: Self.service, account: name)
        if FileManager.default.fileExists(atPath: marker.path) {
            try FileManager.default.removeItem(at: marker)
        }
    }

    private func markerURL(_ name: String) throws -> URL {
        guard Self.isValidName(name) else {
            throw KeyVaultError(code: "BAD_ARGS", message: "bad vault name")
        }
        return markerDirectory.appendingPathComponent("keyvault-\(name).marker")
    }

    private func writeMarker(_ marker: URL) throws {
        try FileManager.default.createDirectory(at: markerDirectory, withIntermediateDirectories: true)
        try Data().write(to: marker, options: .atomic)
    }
}
