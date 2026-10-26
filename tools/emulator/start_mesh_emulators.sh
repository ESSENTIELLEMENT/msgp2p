#!/usr/bin/env bash
set -euo pipefail

# tools/emulator/start_mesh_emulators.sh
# Starts netsimd and 3 Android emulators with linked virtual BLE radios for IT-EMU-01/02.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android/Sdk}}"
EMULATOR_BIN="$SDK_ROOT/emulator/emulator"
NETSIMD_BIN="$SDK_ROOT/emulator/netsimd"
ADB_BIN="$SDK_ROOT/platform-tools/adb"

echo "=== msgp2p Android Virtual BLE Mesh Setup (IT-EMU-01/02) ==="

if [[ ! -x "$EMULATOR_BIN" ]]; then
  echo "Error: Android emulator binary not found at $EMULATOR_BIN" >&2
  exit 1
fi

if [[ ! -c /dev/kvm ]]; then
  echo "Warning: /dev/kvm is not accessible. Hardware acceleration is disabled." >&2
  echo "Check nested virtualization settings if emulator starts slowly." >&2
fi

# Ensure previous instances are cleaned up
"$SCRIPT_DIR/kill_mesh_emulators.sh" || true

# 1. Start netsimd if present
if [[ -x "$NETSIMD_BIN" ]]; then
  echo "Starting netsimd packet streamer daemon..."
  "$NETSIMD_BIN" --no-web-ui --no-cli-ui > /tmp/netsimd.log 2>&1 &
  echo $! > /tmp/netsimd.pid
  sleep 1
fi

# Function to launch an emulator instance
launch_emu() {
  local port="$1"
  local avd_name="$2"
  echo "Launching $avd_name on port $port..."
  
  "$EMULATOR_BIN" \
    -avd "$avd_name" \
    -port "$port" \
    -no-window \
    -no-audio \
    -no-boot-anim \
    -gpu swiftshader_indirect \
    -memory 1536 \
    -packet-streamer-endpoint "127.0.0.1:7343" \
    > "/tmp/emulator-$port.log" 2>&1 &
    
  echo $! > "/tmp/emulator-$port.pid"
}

# 2. Launch emulators
# In local development, these ports map to emulator-5554 (Node A), emulator-5556 (Node B), emulator-5558 (Node C)
launch_emu 5554 "my_Pixel_6a"

echo "Emulators triggered. Use adb devices to inspect boot status."
