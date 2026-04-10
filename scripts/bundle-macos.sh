#!/usr/bin/env bash
# Build a macOS .app bundle and package it into a .dmg.
#
# Usage: scripts/bundle-macos.sh <target-triple> <version>
#   e.g. scripts/bundle-macos.sh aarch64-apple-darwin 0.3.5
#
# Assumes `cargo build --release --target <target-triple>` has already
# been run and that create-dmg is installed (`brew install create-dmg`).
#
# Produces:
#   target/macos-bundle/Aira.app/         — self-contained app bundle
#   target/macos-bundle/Aira-<version>-<arch>.dmg
#
# The .app contains both aira-gui (executable) and aira-daemon (sibling
# in Contents/MacOS/) so daemon_manager::locate_daemon_binary() finds
# the daemon next to the GUI on first launch.

set -euo pipefail

TARGET="${1:?target triple required (e.g. aarch64-apple-darwin)}"
VERSION="${2:?version required (e.g. 0.3.5)}"

ARCH=""
case "$TARGET" in
    aarch64-apple-darwin) ARCH="arm64" ;;
    x86_64-apple-darwin)  ARCH="x86_64" ;;
    *) echo "Unsupported target: $TARGET" >&2; exit 1 ;;
esac

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BIN_DIR="$ROOT/target/$TARGET/release"
OUT_DIR="$ROOT/target/macos-bundle"
APP="$OUT_DIR/Aira.app"

if [[ ! -f "$BIN_DIR/aira-gui" ]] || [[ ! -f "$BIN_DIR/aira-daemon" ]]; then
    echo "Error: release binaries not found in $BIN_DIR" >&2
    echo "Run: cargo build --release --target $TARGET -p aira-gui -p aira-daemon -p aira-cli" >&2
    exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$APP/Contents/MacOS"
mkdir -p "$APP/Contents/Resources"

# Binaries — GUI is the main executable, daemon is a sibling, CLI is a
# bonus for power users.
cp "$BIN_DIR/aira-gui" "$APP/Contents/MacOS/aira-gui"
cp "$BIN_DIR/aira-daemon" "$APP/Contents/MacOS/aira-daemon"
if [[ -f "$BIN_DIR/aira" ]]; then
    cp "$BIN_DIR/aira" "$APP/Contents/MacOS/aira"
fi
chmod +x "$APP/Contents/MacOS/"*

# Info.plist with version substituted in.
sed "s/__VERSION__/$VERSION/g" \
    "$ROOT/packaging/macos/Info.plist.template" \
    > "$APP/Contents/Info.plist"

# Icon: convert the PNG asset into .icns via iconutil (Xcode CLT must be
# installed on the runner). We use sips to rescale the source PNG into
# the .iconset structure iconutil expects.
ICONSET_DIR="$OUT_DIR/icon.iconset"
SRC_PNG="$ROOT/crates/aira-gui/assets/icon.png"

if [[ -f "$SRC_PNG" ]] && command -v sips >/dev/null && command -v iconutil >/dev/null; then
    mkdir -p "$ICONSET_DIR"
    for size in 16 32 64 128 256 512; do
        sips -z $size $size "$SRC_PNG" --out "$ICONSET_DIR/icon_${size}x${size}.png" >/dev/null
        dsize=$((size * 2))
        sips -z $dsize $dsize "$SRC_PNG" --out "$ICONSET_DIR/icon_${size}x${size}@2x.png" >/dev/null
    done
    iconutil -c icns "$ICONSET_DIR" -o "$APP/Contents/Resources/icon.icns"
    rm -rf "$ICONSET_DIR"
else
    echo "Warning: icon.png or sips/iconutil missing — bundle will have no icon" >&2
fi

# Remove the quarantine xattr so we don't ship it inside the DMG.
xattr -cr "$APP" 2>/dev/null || true

# DMG packaging. create-dmg is a shell script available via
# `brew install create-dmg`.
DMG_NAME="Aira-${VERSION}-${ARCH}.dmg"
DMG_PATH="$OUT_DIR/$DMG_NAME"

if command -v create-dmg >/dev/null; then
    create-dmg \
        --volname "Aira ${VERSION}" \
        --window-size 500 320 \
        --icon-size 96 \
        --icon "Aira.app" 125 160 \
        --app-drop-link 375 160 \
        --no-internet-enable \
        "$DMG_PATH" \
        "$APP" || {
            # create-dmg is flaky in CI (AppleScript race). Fall back to
            # hdiutil if it fails.
            echo "create-dmg failed — falling back to hdiutil" >&2
            hdiutil create -volname "Aira ${VERSION}" -srcfolder "$APP" \
                -ov -format UDZO "$DMG_PATH"
        }
else
    echo "create-dmg not found, using hdiutil" >&2
    hdiutil create -volname "Aira ${VERSION}" -srcfolder "$APP" \
        -ov -format UDZO "$DMG_PATH"
fi

# SHA256
( cd "$OUT_DIR" && shasum -a 256 "$DMG_NAME" > "${DMG_NAME}.sha256" )

echo "Built: $DMG_PATH"
