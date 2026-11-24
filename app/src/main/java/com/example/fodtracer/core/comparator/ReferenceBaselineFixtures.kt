package com.example.fodtracer.core.comparator

import com.example.fodtracer.domain.models.*

/**
 * Deterministic reference diagnostic fixtures for unit/comparator verification without requiring two physical devices.
 */
object ReferenceBaselineFixtures {

    fun createWorkingCustomRomBaseline(): DiagnosticSession {
        val now = 1_760_000_000_000L
        return DiagnosticSession(
            sessionId = "REF-CUSTOM-ROM-001",
            label = "Reference Custom ROM (Working FOD)",
            createdAtCivilMs = now,
            updatedAtCivilMs = now,
            environment = DeviceEnvironment(
                model = "Device-Ref",
                manufacturer = "OEM",
                brand = "OEM",
                device = "ref_udfps",
                hardware = "qcom",
                board = "lahaina",
                socManufacturer = "Qualcomm",
                socModel = "SM8350",
                androidVersion = "15",
                sdkInt = 35,
                securityPatch = "2026-01-05",
                buildFingerprint = "custom/ref_udfps/ref_udfps:15/AP4A/1:userdebug/test-keys",
                buildDisplay = "CustomROM-15-UDFPS",
                isTrebleEnabled = true,
                vndkVersion = "35",
                detectedRomType = RomType.CUSTOM_ROM,
                romTypeEvidence = "Reference Custom ROM fixture",
                rootState = RootState.GRANTED_VERIFIED,
                rootProviderHint = "Magisk",
                seLinuxMode = SeLinuxMode.ENFORCING,
                seLinuxContext = "u:r:magisk:s0",
                hasFingerprintFeature = true,
                biometricHardwareStatus = "BIOMETRIC_SUCCESS",
                civilTimestampMs = now
            ),
            probeResults = listOf(
                ProbeResult(
                    probeId = "probe_overlay",
                    domain = ProbeDomain.OVERLAY,
                    status = DiscoveryStatus.FOUND,
                    accessLevelUsed = AccessLevel.ROOT_SU,
                    summary = "Active UDFPS overlay",
                    items = listOf(
                        ProbeFindingItem(
                            key = "overlay.com.android.systemui.udfps.overlay",
                            value = "enabled=true target=com.android.systemui",
                            location = "cmd overlay list",
                            discoveryStatus = DiscoveryStatus.FOUND,
                            epistemicLevel = EpistemicLevel.PROVED,
                            accessLevel = AccessLevel.ROOT_SU
                        )
                    ),
                    durationMs = 42,
                    civilTimestampMs = now
                ),
                ProbeResult(
                    probeId = "probe_properties",
                    domain = ProbeDomain.PROPERTIES,
                    status = DiscoveryStatus.FOUND,
                    accessLevelUsed = AccessLevel.UNPRIVILEGED_SHELL,
                    summary = "FOD props",
                    items = listOf(
                        ProbeFindingItem(
                            key = "ro.vendor.fingerprint.udfps",
                            value = "true",
                            location = "system_property",
                            discoveryStatus = DiscoveryStatus.FOUND,
                            epistemicLevel = EpistemicLevel.PROVED,
                            accessLevel = AccessLevel.UNPRIVILEGED_SHELL
                        ),
                        ProbeFindingItem(
                            key = "persist.sys.udfps.hbm_type",
                            value = "lhbm",
                            location = "system_property",
                            discoveryStatus = DiscoveryStatus.FOUND,
                            epistemicLevel = EpistemicLevel.PROVED,
                            accessLevel = AccessLevel.UNPRIVILEGED_SHELL
                        )
                    ),
                    durationMs = 25,
                    civilTimestampMs = now
                )
            ),
            components = listOf(
                DiscoveredComponent(
                    id = "COMP-SYSUI-001",
                    name = "SystemUI & UdfpsController Host",
                    domain = ProbeDomain.SYSTEMUI,
                    role = ComponentRole.APPLICATION_SYSTEMUI,
                    partition = PartitionOrigin.SYSTEM_EXT,
                    location = "/system_ext/priv-app/SystemUI",
                    discoveryStatus = DiscoveryStatus.FOUND,
                    epistemicLevel = EpistemicLevel.PROVED
                ),
                DiscoveredComponent(
                    id = "COMP-HAL-002",
                    name = "Biometric / Fingerprint HAL",
                    domain = ProbeDomain.HAL,
                    role = ComponentRole.BIOMETRIC_HAL,
                    partition = PartitionOrigin.VENDOR,
                    location = "/vendor/bin/hw/android.hardware.biometrics.fingerprint-service",
                    discoveryStatus = DiscoveryStatus.FOUND,
                    epistemicLevel = EpistemicLevel.PROVED
                )
            ),
            dependencies = emptyList(),
            evidence = emptyList(),
            liveTrace = LiveTraceData(
                sessionStartedMonotonicNanos = 1_000_000L,
                sessionEndedMonotonicNanos = 5_000_000_000L,
                durationMs = 5000L,
                enrollmentOpened = true,
                enrollmentReturnedWithBiometricCheck = "BIOMETRIC_SUCCESS",
                observedSources = listOf("logcat", "/sys/class/drm/card0-DSI-1/lhbm_mode"),
                inaccessibleSources = emptyList(),
                events = listOf(
                    TimelineEvent("E1", TimelineEventType.ENROLLMENT_OPENED, 1_100_000L, 120L, now, "Intent", "opened", "EV1", ConfidenceLevel.HIGH, ObservationType.STATE_TRANSITION),
                    TimelineEvent("E2", TimelineEventType.UDFPS_UI_DISPLAYED, 1_400_000L, 420L, now, "logcat", "UdfpsController show", "EV2", ConfidenceLevel.HIGH, ObservationType.DIRECT_OBSERVATION),
                    TimelineEvent("E3", TimelineEventType.TOUCH_EVENT_OBSERVED, 2_000_000L, 1020L, now, "logcat", "onPointerDown", "EV3", ConfidenceLevel.HIGH, ObservationType.DIRECT_OBSERVATION),
                    TimelineEvent("E4", TimelineEventType.HBM_ENABLED, 2_040_000L, 1060L, now, "/sys/class/drm/card0-DSI-1/lhbm_mode", "0 -> 1", "EV4", ConfidenceLevel.HIGH, ObservationType.STATE_TRANSITION),
                    TimelineEvent("E5", TimelineEventType.IMAGE_ACQUISITION, 2_250_000L, 1270L, now, "logcat", "onAcquired", "EV5", ConfidenceLevel.HIGH, ObservationType.DIRECT_OBSERVATION),
                    TimelineEvent("E6", TimelineEventType.SESSION_COMPLETED, 4_800_000L, 3820L, now, "logcat", "enrollment complete", "EV6", ConfidenceLevel.HIGH, ObservationType.DIRECT_OBSERVATION)
                )
            )
        )
    }

    fun createFailingGsiBaseline(): DiagnosticSession {
        val now = 1_760_000_500_000L
        return DiagnosticSession(
            sessionId = "REF-GSI-FAIL-002",
            label = "Reference GSI (HBM / Overlay Failure)",
            createdAtCivilMs = now,
            updatedAtCivilMs = now,
            environment = DeviceEnvironment(
                model = "Device-Ref",
                manufacturer = "OEM",
                brand = "OEM",
                device = "ref_udfps",
                hardware = "qcom",
                board = "lahaina",
                socManufacturer = "Qualcomm",
                socModel = "SM8350",
                androidVersion = "15",
                sdkInt = 35,
                securityPatch = "2026-01-05",
                buildFingerprint = "treble/aosp_arm64/gsi:15/AP4A/2:userdebug/test-keys",
                buildDisplay = "GSI-Treble-15",
                isTrebleEnabled = true,
                vndkVersion = "35",
                detectedRomType = RomType.GSI,
                romTypeEvidence = "Detected treble/aosp_arm64",
                rootState = RootState.GRANTED_VERIFIED,
                rootProviderHint = "Magisk",
                seLinuxMode = SeLinuxMode.ENFORCING,
                seLinuxContext = "u:r:magisk:s0",
                hasFingerprintFeature = true,
                biometricHardwareStatus = "BIOMETRIC_ERROR_NONE_ENROLLED",
                civilTimestampMs = now
            ),
            probeResults = listOf(
                ProbeResult(
                    probeId = "probe_overlay",
                    domain = ProbeDomain.OVERLAY,
                    status = DiscoveryStatus.FOUND,
                    accessLevelUsed = AccessLevel.ROOT_SU,
                    summary = "No active UDFPS overlay",
                    items = emptyList(),
                    durationMs = 38,
                    civilTimestampMs = now
                ),
                ProbeResult(
                    probeId = "probe_properties",
                    domain = ProbeDomain.PROPERTIES,
                    status = DiscoveryStatus.FOUND,
                    accessLevelUsed = AccessLevel.UNPRIVILEGED_SHELL,
                    summary = "FOD props",
                    items = listOf(
                        ProbeFindingItem(
                            key = "ro.vendor.fingerprint.udfps",
                            value = "true",
                            location = "system_property",
                            discoveryStatus = DiscoveryStatus.FOUND,
                            epistemicLevel = EpistemicLevel.PROVED,
                            accessLevel = AccessLevel.UNPRIVILEGED_SHELL
                        )
                    ),
                    durationMs = 20,
                    civilTimestampMs = now
                )
            ),
            components = listOf(
                DiscoveredComponent(
                    id = "COMP-SYSUI-001",
                    name = "SystemUI & UdfpsController Host",
                    domain = ProbeDomain.SYSTEMUI,
                    role = ComponentRole.APPLICATION_SYSTEMUI,
                    partition = PartitionOrigin.SYSTEM_EXT,
                    location = "/system_ext/priv-app/SystemUI",
                    discoveryStatus = DiscoveryStatus.FOUND,
                    epistemicLevel = EpistemicLevel.PROVED
                ),
                DiscoveredComponent(
                    id = "COMP-HAL-002",
                    name = "Biometric / Fingerprint HAL",
                    domain = ProbeDomain.HAL,
                    role = ComponentRole.BIOMETRIC_HAL,
                    partition = PartitionOrigin.VENDOR,
                    location = "/vendor/bin/hw/android.hardware.biometrics.fingerprint-service",
                    discoveryStatus = DiscoveryStatus.FOUND,
                    epistemicLevel = EpistemicLevel.PROVED
                )
            ),
            dependencies = emptyList(),
            evidence = emptyList(),
            liveTrace = LiveTraceData(
                sessionStartedMonotonicNanos = 1_000_000L,
                sessionEndedMonotonicNanos = 5_000_000_000L,
                durationMs = 5000L,
                enrollmentOpened = true,
                enrollmentReturnedWithBiometricCheck = "BIOMETRIC_ERROR_NONE_ENROLLED",
                observedSources = listOf("logcat", "/sys/class/drm/card0-DSI-1/lhbm_mode"),
                inaccessibleSources = emptyList(),
                events = listOf(
                    TimelineEvent("E1", TimelineEventType.ENROLLMENT_OPENED, 1_100_000L, 120L, now, "Intent", "opened", "EV1", ConfidenceLevel.HIGH, ObservationType.STATE_TRANSITION),
                    TimelineEvent("E2", TimelineEventType.TOUCH_EVENT_OBSERVED, 2_000_000L, 1020L, now, "logcat", "onPointerDown", "EV2", ConfidenceLevel.HIGH, ObservationType.DIRECT_OBSERVATION),
                    TimelineEvent("E3", TimelineEventType.ERROR, 3_200_000L, 2220L, now, "logcat", "Biometric acquisition timeout", "EV3", ConfidenceLevel.HIGH, ObservationType.DIRECT_OBSERVATION)
                )
            ),
            anomalies = listOf(
                AnomalyRecord(
                    id = "ANOM-NO-HBM-ON-TOUCH",
                    title = "Touch observed during enrollment without HBM activation",
                    description = "HBM remained 0 during finger down.",
                    componentId = "COMP-DISP-001",
                    componentName = "Display / HBM Controller",
                    severity = AnomalySeverity.HIGH,
                    epistemicLevel = EpistemicLevel.CORRELATED,
                    justifyingSources = listOf("logcat", "/sys/class/drm/card0-DSI-1/lhbm_mode"),
                    evidenceIds = listOf("EV2")
                )
            )
        )
    }
}
