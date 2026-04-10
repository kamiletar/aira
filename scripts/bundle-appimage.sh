#!/usr/bin/env bash
# Build a Linux AppImage from release binaries.
#
# Usage: scripts/bundle-appimage.sh <version>
#   e.g. scripts/bundle-appimage.sh 0.3.5
#
# Requires:
#   - target/release/{aira-gui,aira-daemon,aira}  (cargo build --release)
#   - linuxdeploy and linuxdeploy-plugin-gtk on PATH (downloaded by the
#     workflow before invocation).
#
# Produces:
#   target/appimage/Aira-<version>-x86_64.AppImage
#   target/appimage/Aira-<version>-x86_64.AppImage.sha256

set -euo pipefail

VERSION="${1:?version required (e.g. 0.3.5)}"
# Optional target triple (e.g. x86_64-unknown-linux-gnu). When present,
# binaries are expected under target/<triple>/release; otherwise under
# target/release. The release.yml workflow always passes the triple.
TARGET="${2:-}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [[ -n "$TARGET" ]]; then
    BIN_DIR="$ROOT/target/$TARGET/release"
else
    BIN_DIR="$ROOT/target/release"
fi
OUT_DIR="$ROOT/target/appimage"
APPDIR="$OUT_DIR/AppDir"

if [[ ! -f "$BIN_DIR/aira-gui" ]] || [[ ! -f "$BIN_DIR/aira-daemon" ]]; then
    echo "Error: release binaries not found in $BIN_DIR" >&2
    echo "Run: cargo build --release -p aira-gui -p aira-daemon -p aira-cli" >&2
    exit 1
fi

rm -rf "$OUT_DIR"
mkdir -p "$APPDIR/usr/bin"
mkdir -p "$APPDIR/usr/share/applications"
mkdir -p "$APPDIR/usr/share/icons/hicolor/512x512/apps"

# Binaries
cp "$BIN_DIR/aira-gui" "$APPDIR/usr/bin/"
cp "$BIN_DIR/aira-daemon" "$APPDIR/usr/bin/"
if [[ -f "$BIN_DIR/aira" ]]; then
    cp "$BIN_DIR/aira" "$APPDIR/usr/bin/"
fi
chmod +x "$APPDIR/usr/bin/"*

# .desktop entry (required by linuxdeploy)
cp "$ROOT/packaging/linux/aira.desktop" "$APPDIR/usr/share/applications/aira.desktop"

# Icon — drop the source PNG into the hicolor directory and also at the
# AppDir root (linuxdeploy expects both locations).
SRC_PNG="$ROOT/crates/aira-gui/assets/icon.png"
if [[ -f "$SRC_PNG" ]]; then
    cp "$SRC_PNG" "$APPDIR/usr/share/icons/hicolor/512x512/apps/aira.png"
    cp "$SRC_PNG" "$APPDIR/aira.png"
else
    echo "Warning: crates/aira-gui/assets/icon.png missing — using placeholder" >&2
    touch "$APPDIR/aira.png"
fi

# AppRun entry script (loads the GUI, sets LD_LIBRARY_PATH).
cp "$ROOT/packaging/linux/AppRun" "$APPDIR/AppRun"
chmod +x "$APPDIR/AppRun"

# Symlink desktop entry to the root (also expected by linuxdeploy).
ln -sf usr/share/applications/aira.desktop "$APPDIR/aira.desktop"

# Run linuxdeploy. The GTK plugin bundles libgtk-3 and friends so the
# AppImage works across glibc versions. Output goes to cwd by default.
cd "$OUT_DIR"
OUTPUT="Aira-${VERSION}-x86_64.AppImage" \
    linuxdeploy \
        --appdir AppDir \
        --desktop-file "AppDir/usr/share/applications/aira.desktop" \
        --icon-file "AppDir/aira.png" \
        --plugin gtk \
        --output appimage

# linuxdeploy names the output Aira-<version>-x86_64.AppImage via the
# OUTPUT env var above. sha256 for integrity.
ARTIFACT="Aira-${VERSION}-x86_64.AppImage"
if [[ ! -f "$ARTIFACT" ]]; then
    # Some linuxdeploy versions ignore OUTPUT and use a default name.
    found=$(ls Aira*.AppImage 2>/dev/null | head -1 || true)
    if [[ -n "$found" ]]; then
        mv "$found" "$ARTIFACT"
    else
        echo "Error: linuxdeploy did not produce an AppImage" >&2
        exit 1
    fi
fi

sha256sum "$ARTIFACT" > "${ARTIFACT}.sha256"
echo "Built: $OUT_DIR/$ARTIFACT"
