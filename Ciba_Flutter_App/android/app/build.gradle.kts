plugins {
    id("com.android.application")
    // START: FlutterFire Configuration
    id("com.google.gms.google-services")
    // END: FlutterFire Configuration
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

android {
    namespace = "com.cicada.aegis.aegis_ciba_companion"
    compileSdk = 36
    ndkVersion = "27.0.12077973"

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
        isCoreLibraryDesugaringEnabled = true
    }

    kotlinOptions {
        jvmTarget = JavaVersion.VERSION_11.toString()
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.cicada.aegis.aegis_ciba_companion"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = 24
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName

        // Restrict native ABIs to arm64-v8a (the only target we cross-compiled liboqs for).
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    // NDK CMake build for liboqs JNI bridge (oqs_jni.so).
    // Links the cross-compiled liboqs.a static library to enable
    // ML-DSA-65 (FIPS 204) and ML-KEM-768 (FIPS 203) on-device.
    // Built by: scripts/build_liboqs_android.sh
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1+"
        }
    }

    buildTypes {
        release {
            // TODO: Add your own signing config for the release build.
            // Signing with the debug keys for now, so `flutter run --release` works.
            signingConfig = signingConfigs.getByName("debug")
        }
    }
}

flutter {
    source = "../.."
}

dependencies {
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")

    // Play Integrity API — per-decision device attestation (Phase 6).
    implementation("com.google.android.play:integrity:1.4.0")

    // AndroidX Biometric — CryptoObject-bound biometric authentication (Phase 4).
    // This replaces the boolean-only local_auth approach with hardware-bound
    // key unlocking that requires a live biometric scan.
    implementation("androidx.biometric:biometric:1.2.0-alpha05")

    // Fragment KTX — required for BiometricPrompt on FlutterFragmentActivity.
    implementation("androidx.fragment:fragment-ktx:1.8.5")

    // Firebase Cloud Messaging — required for native HitlFirebaseMessagingService.
    // The Flutter plugin provides this at runtime, but Kotlin compilation
    // needs it as an explicit dependency for the native FCM handler.
    implementation("com.google.firebase:firebase-messaging:24.1.0")
}
