#!/bin/zsh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
BUILD="$ROOT/build"
APP="$BUILD/SingBoxSwitch.app"
INSTALL="$HOME/Applications/SingBoxSwitch.app"

mkdir -p "$BUILD"
swiftc -swift-version 5 -parse-as-library -O \
  -framework AppKit \
  -framework Foundation \
  -framework UniformTypeIdentifiers \
  "$ROOT/Sources/SingBoxSwitch/main.swift" \
  -o "$BUILD/SingBoxSwitch"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$BUILD/SingBoxSwitch" "$APP/Contents/MacOS/SingBoxSwitch"
cp "$ROOT/Info.plist" "$APP/Contents/Info.plist"
chmod 755 "$APP/Contents/MacOS/SingBoxSwitch"
codesign --force --deep --sign - "$APP" >/dev/null

mkdir -p "$HOME/Applications"
rm -rf "$INSTALL"
ditto "$APP" "$INSTALL"

echo "Installed: $INSTALL"
