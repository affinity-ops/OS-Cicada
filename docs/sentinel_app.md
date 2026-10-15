# Cicada Sentinel Companion App: Architecture & Post-Mortem

This document serves as the authoritative definition of the **Cicada Sentinel** Mobile Application's intended behavior, its integration with the Master Admin Panel, and its underlying Zero-Trust architectural decisions.

## 1. What is the Sentinel App?

The Cicada Sentinel app is a strictly secured, Zero-Trust mobile companion designed specifically for **Vendor Oversight Authorization**. While the *Aegis App* is used by end-customer operators to approve individual agent actions via CIBA, the *Sentinel App* is used exclusively by the **Cicada Core Team** to log into the global Master Admin Panel (Port 3005).

It acts as the cryptographic gatekeeper to the vendor control plane. Its sole purpose is to enforce biometric authentication upon the human administrator and cryptographically sign a challenge payload using a hardware-bound PQC (Post-Quantum Cryptography) hybrid signature (Ed25519 + ML-DSA-65).

## 2. The Sentinel Zero-Trust Handshake

The Sentinel app pairs directly with the Master Admin Panel through a zero-secret QR handshake:

1. **The Challenge:** The Master Admin login page generates an ephemeral session ID and a cryptographic challenge string, encoding them (along with the host IP address) into a QR code.
2. **The Scan:** The vendor administrator opens the Sentinel app and scans the QR code.
3. **The Biometric Lock:** Upon successfully reading the QR payload, the app halts the UI and demands native Biometric Authentication (FaceID/Fingerprint) from the device hardware.
4. **The Signature:** If biometrics pass, the app retrieves the private Ed25519 key from the device's secure enclave and the ML-DSA-65 post-quantum signing key (via native liboqs bridge). It signs the challenge string with both algorithms (hybrid dual-signature).
5. **The Transmission:** The app POSTs the session ID, challenge ID, and cryptographic signatures directly back to the Master Admin Panel via the local network using the dynamic host IP embedded in the QR code.
6. **The Validation:** The Master Admin Panel verifies the signatures against the administrator's registered public keys. If valid, the browser session is authenticated, and the administrator is granted access to the global dashboard.

## 3. UI/UX Security Architecture

To ensure physical security and project a premium, cutting-edge aesthetic, the Sentinel app implements the following UI paradigms:

### 3.1 Cinematic Boot Sequence (Splash Screen)
When launched, the app does not immediately expose the scanner. Instead, it presents a high-tech "boot sequence" splash screen (dark grey `#0F0F13` with neon orange `#xFFFF8A00` accents). A simulated terminal cycles through security initialization steps (`INITIALIZING SECURE ENCLAVE...`, `VERIFYING HARDWARE INTEGRITY...`, `LOADING POST-QUANTUM CRYPTOGRAPHY...`, `ED25519 + ML-DSA-65 HYBRID READY.`). This sequence communicates the serious, enterprise-grade nature of the application before cross-fading into the main UI.

### 3.2 Biometric UI Lock (Hidden Identity)
Technically, public keys are safe to display. However, from a physical Zero-Trust perspective, exposing a device's unique cryptographic identity to anyone who picks up an unlocked phone expands the attack surface for targeted social engineering or identity mapping. 
Therefore, the Sentinel app **permanently hides the Ed25519 and ML-DSA-65 public keys** by default. At the bottom of the screen, a padlock icon and a "Reveal Device Identity" button are displayed. Tapping this button triggers a strict `local_auth` biometric challenge. Only upon successful biometric verification are the keys rendered on the screen.

## 4. BLoC Architecture & Service Decoupling

Following the structural patterns established by the Aegis app, Sentinel implements a strict separation of concerns using `flutter_bloc`. The monolithic structure was decomposed into:

*   **`core/`**: Contains decoupled service wrappers (`SecureStorage`, `Ed25519Service`, `MlDsaService`, `BiometricService`, `AuthClient`). These isolate hardware interaction and external dependencies.
*   **`features/`**: Contains UI screens and their dedicated BLoC state machines (e.g., `AuthBloc` handles the challenge-signing lifecycle deterministically without fragile `setState` UI loops).
*   **`config/`**: Centralizes API endpoint definitions, storage keys, and the `SentinelTheme` design tokens.
*   **`widgets/`**: Reusable UI components (`DeviceStatusBadge`, `KeyDisplayCard`, `AuthorizeButton`, `GridBackground`).

Dependencies are injected at the root of the application via `MultiRepositoryProvider` and `MultiBlocProvider`, ensuring a clean, testable, and robust enterprise-grade architecture.

## 5. Build & Distribution

*   **Repository Location:** `/sentinel_flutter_app` (Completely decoupled from the `/Ciba_Flutter_App` Aegis repository).
*   **Compilation:** The app requires Flutter SDK 3.x, Kotlin 2.1.0, and a minimum Android SDK of 24 to support the required security plugins (`local_auth`, `mobile_scanner`).
*   **Distribution:** The production binary (`app-release.apk`) is automatically compiled and copied to the central distribution server (`apk_server` running on Port 3004) as `sentinel-app-v1.apk`. It can be downloaded directly to any physical mobile device on the local network via `http://<HOST-IP>:3004/sentinel-app-v1.apk`.

## 6. Plugin Dependencies

*   `mobile_scanner`: High-performance QR/Barcode scanning via camera.
*   `local_auth`: Hooks directly into Android/iOS native biometric APIs (FaceID, Fingerprint).
*   `flutter_secure_storage`: Ensures private keys are vaulted inside the hardware Keystore/Keychain, preventing extraction on non-rooted devices.
*   `cryptography`: Replaced the deprecated `ed25519_edwards` package, providing the primary Ed25519 cryptographic signing layer with a path for X25519 expansion.
*   `flutter_bloc`: Provides deterministic, predictable state management.
*   `http`: Handles the local network POST transmission to the Master Admin Panel.
