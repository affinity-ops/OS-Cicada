# Cicada Aegis — Android NDK CMake for liboqs JNI Bridge
#
# Builds oqs_jni.so which is loaded by MainActivity.kt via
# System.loadLibrary("oqs_jni").
#
# Prerequisites:
#   1. Download and build liboqs for Android:
#      git clone https://github.com/open-quantum-safe/liboqs.git
#      cd liboqs && mkdir build-android && cd build-android
#      cmake -DCMAKE_TOOLCHAIN_FILE=$ANDROID_NDK/build/cmake/android.toolchain.cmake \
#            -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-24 \
#            -DOQS_ENABLE_SIG_ML_DSA=ON -DOQS_ENABLE_KEM_ML_KEM=ON \
#            -DCMAKE_BUILD_TYPE=Release ..
#      cmake --build . --parallel
#
#   2. Copy the built library and headers:
#      cp lib/liboqs.a ${PROJECT_DIR}/liboqs/lib/arm64-v8a/
#      cp -r include/oqs ${PROJECT_DIR}/liboqs/include/
#
#   3. Add to build.gradle.kts:
#      android {
#          externalNativeBuild {
#              cmake { path = file("src/main/cpp/CMakeLists.txt") }
#          }
#      }

cmake_minimum_required(VERSION 3.22)
project(oqs_jni C)

# Path to pre-built liboqs static library.
set(OQS_LIB_DIR "${CMAKE_SOURCE_DIR}/liboqs/lib/${ANDROID_ABI}")
set(OQS_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/liboqs/include")

# Import liboqs as a pre-built static library.
add_library(oqs STATIC IMPORTED)
set_target_properties(oqs PROPERTIES
    IMPORTED_LOCATION "${OQS_LIB_DIR}/liboqs.a"
    INTERFACE_INCLUDE_DIRECTORIES "${OQS_INCLUDE_DIR}"
)

# Build the JNI bridge shared library.
add_library(oqs_jni SHARED oqs_jni.c)
target_include_directories(oqs_jni PRIVATE "${OQS_INCLUDE_DIR}")
target_link_libraries(oqs_jni oqs log)
