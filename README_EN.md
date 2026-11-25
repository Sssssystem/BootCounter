English | [简体中文](README.md)

# BootCounter — Tamper-Evident Windows Boot & Wake Audit Counter

A lightweight, zero-dependency Windows 11 Fluent Design desktop utility that accurately tracks every system boot, restart, Fast Startup power-on, and lid-open / sleep wake since installation (first install counts as `1`), backed by hardware-grade anti-tamper and anti-reinstall verification.

## Features

### 1. Comprehensive Boot & Wake Tracking

* **Counts from Install (`1`)**: Initial setup immediately records the first session as `#1`.

* **Covers All Wake Paths**: Combines Windows kernel `System` Event Logs (`Kernel-General 12` cold boot/restart, `Kernel-Boot 27` Fast Startup, `Power-Troubleshooter 1` sleep/lid wake) with 64-bit `GetTickCount64()`, deduplicating rapid underlying events within 60 seconds.

* **Dual-Channel Event Query**: Separates power/clear-log queries from clock-sync queries so routine NTP time syncs never crowd out historical boot records.

* **Windows Autostart**: Supports Silent Autostart, Show Window on Boot, or Off, automatically repairing the registry path if moved.

### 2. Hardware-Grade Anti-Tamper & Anti-Reinstall Protection (v1.1)

* **Permanent Reset Counter**: Every count reset permanently increments the non-resettable Total Resets counter, backed by a registry anti-rollback anchor.

* **Telegram-Style 6-Emoji Anti-Reinstall Fingerprint**: Uses the OS cryptographic RNG (`os.urandom(32)` / Windows `BCryptGenRandom`) to generate a hidden 256-bit install ID (never displayed in the UI, logged only in `audit.log` and exported reports), combined with a per-install seal (`install_seal.dat`) and the TPM 2.0 public key hash to derive 6 high-contrast emojis ($64^6 \approx 68.7$ billion combinations). Uninstalling or overwriting backups immediately changes the fingerprint.

* **TPM 2.0 Hardware Key & Encrypted Config**:

  * Creates a non-exportable ECDSA-P256 private key inside the motherboard **TPM 2.0** chip (`Microsoft Platform Crypto Provider`) bound to the 6-emoji fingerprint; automatically destroyed on uninstall.

  * Encrypts the entire `state.json` configuration file via Windows **DPAPI** (`CryptProtectData`), leaving zero plaintext fields on disk (automatically falls back to DPAPI on non-TPM PCs).

  * Verifies the application binary **SHA-256** hash and **TPM 2.0 hardware signature** on every launch—if the binary itself is altered, execution halts immediately, while normal config updates (changing password, recording boots) work freely.

  * Built-in **anti-debugging** (`IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtSetInformationThread(ThreadHideFromDebugger)`, and Python tracer checks), with native C/C++ machine-code compilation via Nuitka.

* **System-Level Anomaly Auditing**:

  * Detects manual clearing of Windows Event Logs (`EventID 104`).

  * Detects large manual system clock jumps (`EventID 1`, > 5 minutes).

  * Monotonic `EventRecordID` tracking prevents bypassing via clock rollback.

  * Hash-chained boot history + HMAC signature + registry anti-rollback anchor.

* **Audited Alert Dismissal**: Active UI alerts can be dismissed after identity verification, while the dismissal timestamp, method, and original alert details remain permanently logged in `audit.log` and exported reports.

### 3. Flexible Multi-Method Verification

* **Admin Password**: Stored with `PBKDF2-HMAC-SHA256` (120,000 iterations, salted), plus a built-in 16-character OS-RNG **Strong Password Generator**.

* **TOTP Authenticator with Built-in QR Code**: Zero-dependency RFC 6238 TOTP & pure-vector QR code right inside the setup wizard—scan directly with **iPhone Camera / Apple Passwords (Face ID)**, Google Authenticator, or Microsoft Authenticator.

* **Windows Hello**: Native Windows `UserConsentVerifier` integration supporting fingerprint, face recognition, or PIN.

* **Custom Policy Combinations**: Choose "Any selected method can clear", "All selected methods required", "Disable clearing completely", or irreversible "Permanent Lock".

### 4. Windows 11 Native Experience & Bilingual UI

* **Auto Language Detection**: Automatically uses Simplified Chinese on Chinese Windows, and **defaults to English on English and all other non-Chinese systems** (manually switchable in Settings).

* **Per-Monitor V2 High-DPI**: Crisp rendering on 2K/4K displays at 125%–200% scaling with resizable, auto-centered windows.

* **System Tray & Async Sync**: Minimizes cleanly to the Windows system tray with live boot-count tooltips and runs event log synchronization asynchronously with a slim Fluent progress bar.

## Repository Structure

```
BootCounter/
├── app.ico                          # Windows 11 Fluent multi-resolution icon
├── boot_counter.py                  # Main application source (Python 3 + Tkinter, zero runtime deps)
├── setup_msi.py                     # cx_Freeze build configuration
├── BootCounter_Setup.iss            # Inno Setup 6 modern bilingual installer script
├── ChineseSimplified.isl            # Simplified Chinese installer language pack
├── build_installer.bat              # Local fast installer build script (cx_Freeze)
├── build_nuitka_installer.bat       # Local native C/C++ machine code build script (Nuitka)
├── reset_for_testing.bat            # Developer testing script: wipe local data, registry & TPM test key
├── README.md                        # Chinese documentation
├── README_EN.md                     # English documentation
└── .github/
    └── workflows/
        └── release-msi.yml          # GitHub Actions automated Nuitka build & Release workflow

```

## Installation & Building

### Option 1: Download Prebuilt Installer

Download the latest `BootCounter_Setup_1.1.0_amd64.exe` from the [**Releases**](https://www.google.com/search?q=https://github.com/Sssssystem/BootCounter/releases) page and run it (automatically matches system language and lets you choose "All Users" or "Current User").

### Option 2: Build Locally on Windows

1. Install [Python 3.12](https://www.python.org/downloads/) (check `Add Python to PATH`).

2. Place all repository files in the same folder:

   * **Native C/C++ Machine Code (Recommended)**: Double-click `build_nuitka_installer.bat`.

   * **Fast Freeze Build**: Double-click `build_installer.bat`.

3. The compiled installer will be generated at `dist\BootCounter_Setup_1.1.0_amd64.exe`.

### Resetting for Testing

To wipe all local test records, logs, registry anchors, and the dedicated TPM test key on your own test PC, uninstall BootCounter first and then run `reset_for_testing.bat`.

## Acknowledgements

Powered by Google Gemini

## License

MIT License