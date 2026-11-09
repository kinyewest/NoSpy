# NoSpy — Rust AntiSpyware & Endpoint Security

NoSpy is a lightweight, high-performance Windows AntiSpyware, De-Source Static Analyzer, and Ransomware Protection desktop application built in **Rust** (Tauri v2) with a frameless **Frosted Black & Gray GlassUI**.

## Features

- **Real-Time Detection Guard**: Continuously monitors process spawns, network sockets, startup hooks, and ransomware canary traps in real time.
- **De-Source & Static Binary Inspector**: Extracts ASCII/UTF-16LE strings, PE headers, Shannon entropy (`bits/byte`), Base64 obfuscated payloads, embedded URLs, and high-risk Win32 API imports (`VirtualAllocEx`, `WriteProcessMemory`, `SetWindowsHookEx`, `CryptUnprotectData`, etc.) from any executable or script.
- **Groq AI Assisted Scanning**: Optional integration with Groq (`llama-3.3-70b-versatile`) to analyze de-sourced binaries, scripts, and system scan findings.
- **Ransomware Protection Shield**:
  - **Canary Honeypot Guard**: Cryptographic SHA-256 decoy trap files in `Documents`, `Desktop`, `Pictures`, `Downloads`, and `CanaryVault`.
  - **Shadow Copy (VSS) Guard**: Monitors for `vssadmin`, `wmic shadowcopy`, `wbadmin`, and `bcdedit` recovery tampering.
  - **Extension & Note Filter**: Flags known ransomware extensions and ransom notes.
- **Live Resource Telemetry Graph**: Smooth cubic-Bezier spline graphs for Processor Load and Memory Allocation with per-application CPU & RAM breakdown.
- **Quarantine Vault**: Isolates suspicious files with XOR obfuscation and SHA-256 verification.

## Building from Source

```bash
cd src-tauri
cargo build --release
```
