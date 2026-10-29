#!/usr/bin/env bash
# Builds the iOS Keychain vault and runs its XCTests as a Swift package (macOS CI). The files have no Flutter
# dependency, so this needs neither Flutter nor CocoaPods. Module name msgp2p_flutter for @testable import.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/Sources/msgp2p_flutter" "$work/Tests/KeychainVaultTests"
cp "$root/packages/msgp2p_flutter/ios/Classes/KeychainVault.swift" "$work/Sources/msgp2p_flutter/"
cp "$root/packages/msgp2p_flutter/ios/Tests/KeychainVaultTests.swift" "$work/Tests/KeychainVaultTests/"
cat > "$work/Package.swift" <<'SWIFT'
// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "msgp2p_flutter",
    platforms: [.macOS(.v12), .iOS(.v14)],
    targets: [
        .target(name: "msgp2p_flutter"),
        .testTarget(name: "KeychainVaultTests", dependencies: ["msgp2p_flutter"]),
    ]
)
SWIFT
cd "$work" && swift test
