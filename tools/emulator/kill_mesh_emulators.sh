#!/usr/bin/env bash
# tools/emulator/kill_mesh_emulators.sh
# Shuts down emulators and netsim instances.

SDK_ROOT="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-$HOME/Android/Sdk}}"
ADB_BIN="$SDK_ROOT/platform-tools/adb"

echo "Shutting down active emulators..."

for port in 5554 5556 5558; do
  if [[ -f "/tmp/emulator-$port.pid" ]]; then
    pid=$(cat "/tmp/emulator-$port.pid")
    kill "$pid" 2>/dev/null || true
    rm -f "/tmp/emulator-$port.pid"
  fi
  if command -v "$ADB_BIN" >/dev/null 2>&1; then
    "$ADB_BIN" -s "emulator-$port" emu kill 2>/dev/null || true
  fi
done

if [[ -f /tmp/netsimd.pid ]]; then
  kill $(cat /tmp/netsimd.pid) 2>/dev/null || true
  rm -f /tmp/netsimd.pid
fi

pkill -f "emulator.*-port 555" 2>/dev/null || true
pkill -f "netsimd" 2>/dev/null || true

echo "All emulator mesh processes stopped."
