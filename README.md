# FodTracer

Android native **FOD / UDFPS (Fingerprint On Display)** investigation, live enrollment tracing, Custom ROM vs. GSI comparator, and GSI-only feasibility analyzer built with Kotlin & Jetpack Compose.

## Architecture & Capabilities

- **Phase 1 — Cold Investigation**: 12 non-destructive, read-only probes (`hardware`, `biometric`, `framework`, `systemui`, `hal`, `vendor`, `display`, `kernel`, `touch`, `overlay`, `selinux`, `properties`).
- **Phase 2 — Live Enrollment Tracing**: `specialUse` ForegroundService (`FodLiveTracerService`) observing targeted FOD telemetry during Android system biometric enrollment (`ACTION_BIOMETRIC_ENROLL`), paired with `BiometricManager` post-return verification.
- **Epistemic Integrity**: Every finding, component, dependency link, anomaly, and hypothesis is explicitly tagged (`PROVED`, `CORRELATED`, `HYPOTHESIS`, `INACCESSIBLE`). Restricted or SELinux-denied probes are never treated as absent hardware.
- **Custom ROM vs. GSI Comparator**: Structural & behavioral relative-timeline comparison of two verified ZIP archives, distinguishing benign build metadata from critical divergences.
- **GSI Solution & Optional AI Advisor**: Deterministic classification (`GSI_ONLY_CONFIGURATION`, `GSI_ONLY_RUNTIME`, `OUTSIDE_GSI_SCOPE`) plus optional, consent-gated Firebase AI Logic (`gemini-3.8-flash`, `ThinkingLevel.HIGH`) grounded exclusively in extracted diagnostic facts.
- **Structured Archives (`/sdcard/FODtracer/` & SAF)**: SHA-256 verified ZIP export/import with Zip-Slip, duplicate-entry, schema-version, and size-cap protections, plus non-destructive anonymization.

## Building & Testing

This repository builds cleanly out-of-the-box without requiring `google-services.json`. When Firebase configuration is absent (such as local forks or CI), all diagnostic, comparator, archive, and deterministic solution features remain 100% operational while the optional AI Advisor disables gracefully.

```bash
gradle :app:testDebugUnitTest
gradle :app:assembleDebug
```
