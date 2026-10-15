#!/usr/bin/env bash
# ──────────────────────────────────────────────────────────────────────────────
# Cicada Aegis — Build liboqs for Android (ARM64)
#
# Compiles liboqs (Open Quantum Safe) as a static library for Android ARM64,
# then copies the artefacts into the Flutter project's cpp/ directory so the
# NDK CMake build can link oqs_jni.so against it.
#
# Prerequisites:
#   - Android NDK (installed via Android Studio or sdkmanager)
#   - cmake ≥ 3.22
#   - git
#
# Usage:
#   ./scripts/build_liboqs_android.sh
#
# Output:
#   Ciba_Flutter_App/android/app/src/main/cpp/liboqs/lib/arm64-v8a/liboqs.a
#   Ciba_Flutter_App/android/app/src/main/cpp/liboqs/include/oqs/
# ──────────────────────────────────────────────────────────────────────────────
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CPP_DIR="$PROJECT_DIR/android/app/src/main/cpp"
BUILD_DIR="$PROJECT_DIR/.liboqs-build"
OUTPUT_LIB_DIR="$CPP_DIR/liboqs/lib/arm64-v8a"
OUTPUT_INC_DIR="$CPP_DIR/liboqs/include"

# ── Locate Android NDK ──────────────────────────────────────────────────────

if [ -n "${ANDROID_NDK_HOME:-}" ]; then
  NDK_PATH="$ANDROID_NDK_HOME"
elif [ -n "${ANDROID_HOME:-}" ] && [ -d "$ANDROID_HOME/ndk" ]; then
  NDK_PATH="$ANDROID_HOME/ndk/$(ls "$ANDROID_HOME/ndk/" | sort -V | tail -1)"
elif [ -d "$HOME/Library/Android/sdk/ndk" ]; then
  NDK_PATH="$HOME/Library/Android/sdk/ndk/$(ls "$HOME/Library/Android/sdk/ndk/" | sort -V | tail -1)"
else
  echo "✗ FATAL: Cannot find Android NDK. Set ANDROID_NDK_HOME or install via Android Studio."
  exit 1
fi

TOOLCHAIN="$NDK_PATH/build/cmake/android.toolchain.cmake"
if [ ! -f "$TOOLCHAIN" ]; then
  echo "✗ FATAL: NDK toolchain not found at $TOOLCHAIN"
  exit 1
fi

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Cicada Aegis — liboqs Android ARM64 Build                  ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "  NDK:         $NDK_PATH"
echo "  Toolchain:   $TOOLCHAIN"
echo "  Output lib:  $OUTPUT_LIB_DIR"
echo "  Output inc:  $OUTPUT_INC_DIR"
echo ""

# ── Clone or update liboqs ──────────────────────────────────────────────────

LIBOQS_SRC="$BUILD_DIR/liboqs"

if [ -d "$LIBOQS_SRC/.git" ]; then
  echo "[1/4] Updating liboqs source..."
  cd "$LIBOQS_SRC" && git pull --ff-only 2>/dev/null || true
else
  echo "[1/4] Cloning liboqs (Open Quantum Safe)..."
  mkdir -p "$BUILD_DIR"
  cd "$BUILD_DIR"
  git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git
fi

# ── Cross-compile for Android ARM64 ────────────────────────────────────────

echo "[2/4] Cross-compiling liboqs for Android ARM64..."

BUILD_OUT="$BUILD_DIR/build-android-arm64"
rm -rf "$BUILD_OUT"
mkdir -p "$BUILD_OUT"
cd "$BUILD_OUT"

cmake "$LIBOQS_SRC" \
  -DCMAKE_TOOLCHAIN_FILE="$TOOLCHAIN" \
  -DANDROID_ABI=arm64-v8a \
  -DANDROID_PLATFORM=android-24 \
  -DANDROID_STL=c++_static \
  -DCMAKE_BUILD_TYPE=Release \
  -DOQS_ENABLE_SIG_ML_DSA=ON \
  -DOQS_ENABLE_KEM_ML_KEM=ON \
  -DOQS_MINIMAL_BUILD="SIG_ml_dsa_65;KEM_ml_kem_768" \
  -DOQS_BUILD_ONLY_LIB=ON \
  -DOQS_USE_OPENSSL=OFF \
  -DBUILD_SHARED_LIBS=OFF \
  -DCMAKE_POSITION_INDEPENDENT_CODE=ON

cmake --build . --parallel "$(sysctl -n hw.logicalcpu 2>/dev/null || echo 4)"

# ── Copy artefacts to Flutter project ──────────────────────────────────────

echo "[3/4] Installing artefacts to Flutter project..."

mkdir -p "$OUTPUT_LIB_DIR"
mkdir -p "$OUTPUT_INC_DIR"

cp "$BUILD_OUT/lib/liboqs.a" "$OUTPUT_LIB_DIR/"
cp -r "$LIBOQS_SRC/src/oqs" "$OUTPUT_INC_DIR/" 2>/dev/null || true
# Also copy the generated config header
if [ -d "$BUILD_OUT/include/oqs" ]; then
  cp -r "$BUILD_OUT/include/oqs/"* "$OUTPUT_INC_DIR/oqs/" 2>/dev/null || true
fi

# ── Verify ─────────────────────────────────────────────────────────────────

echo "[4/4] Verifying build..."

LIB_SIZE=$(stat -f%z "$OUTPUT_LIB_DIR/liboqs.a" 2>/dev/null || stat -c%s "$OUTPUT_LIB_DIR/liboqs.a" 2>/dev/null)
echo ""
echo "  ✅ liboqs.a built successfully"
echo "     Size: $LIB_SIZE bytes ($(echo "scale=1; $LIB_SIZE / 1048576" | bc)MB)"
echo "     Path: $OUTPUT_LIB_DIR/liboqs.a"
echo ""

# Verify it's actually ARM64
file "$OUTPUT_LIB_DIR/liboqs.a" | head -1

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ BUILD COMPLETE                                          ║"
echo "║                                                              ║"
echo "║  Next steps:                                                 ║"
echo "║  1. Enable cmake in build.gradle.kts:                       ║"
echo "║     android { externalNativeBuild {                          ║"
echo "║       cmake { path = file(\"src/main/cpp/CMakeLists.txt\") }  ║"
echo "║     }}                                                       ║"
echo "║  2. Rebuild APK: flutter build apk --release                 ║"
echo "║  3. Install on device and re-pair                            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
