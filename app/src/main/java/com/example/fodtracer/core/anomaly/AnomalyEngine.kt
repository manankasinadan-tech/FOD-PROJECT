package com.example.fodtracer.core.anomaly

import com.example.fodtracer.domain.models.*

data class AnomalyAnalysisOutput(
    val anomalies: List<AnomalyRecord>,
    val hypotheses: List<HypothesisRecord>
)

/**
 * Deterministic anomaly & hypothesis engine.
 * Never declares a failure solely from inaccessible data or missing logs without monitored source proof.
 */
class AnomalyEngine {

    fun analyze(
        environment: DeviceEnvironment,
        probeResults: List<ProbeResult>,
        components: List<DiscoveredComponent>,
        evidence: List<EvidenceRecord>,
        liveTrace: LiveTraceData?
    ): AnomalyAnalysisOutput {
        val anomalies = mutableListOf<AnomalyRecord>()
        val hypotheses = mutableListOf<HypothesisRecord>()

        val bioProbe = probeResults.firstOrNull { it.domain == ProbeDomain.BIOMETRIC }
        val seLinuxProbe = probeResults.firstOrNull { it.domain == ProbeDomain.SELINUX }
        val overlayProbe = probeResults.firstOrNull { it.domain == ProbeDomain.OVERLAY }
        val displayProbe = probeResults.firstOrNull { it.domain == ProbeDomain.DISPLAY }
        val halComponent = components.firstOrNull { it.role == ComponentRole.BIOMETRIC_HAL }
        val bioComponent = components.firstOrNull { it.role == ComponentRole.BIOMETRIC_SERVICE }

        // 1. Check biometric feature & hardware status (Proved via Android API)
        if (!environment.hasFingerprintFeature) {
            anomalies += AnomalyRecord(
                id = "ANOM-NO-FP-FEATURE",
                title = "PackageManager.FEATURE_FINGERPRINT absent",
                description = "Android framework does not advertise android.hardware.fingerprint feature.",
                componentId = bioComponent?.id,
                componentName = "Framework Biometric Feature",
                severity = AnomalySeverity.CRITICAL,
                epistemicLevel = EpistemicLevel.PROVED,
                justifyingSources = listOf("PackageManager.FEATURE_FINGERPRINT"),
                evidenceIds = evidence.filter { it.resourceType.contains("feature.fingerprint") }.map { it.id },
                possibleCauses = listOf(
                    "Missing android.hardware.fingerprint.xml permission file in /vendor or /system_ext",
                    "Device HAL failed to register fingerprint feature flag"
                ),
                recommendedSteps = listOf(
                    "Check /vendor/etc/permissions/ for fingerprint XML",
                    "Verify Biometric HAL startup in logcat"
                )
            )
        } else if (environment.biometricHardwareStatus.contains("HW_UNAVAILABLE") ||
            environment.biometricHardwareStatus.contains("NO_HARDWARE")
        ) {
            anomalies += AnomalyRecord(
                id = "ANOM-BIO-HW-UNAVAILABLE",
                title = "Biometric hardware unavailable at Framework level",
                description = "BiometricManager reports ${environment.biometricHardwareStatus}.",
                componentId = bioComponent?.id,
                componentName = "BiometricService",
                severity = AnomalySeverity.CRITICAL,
                epistemicLevel = EpistemicLevel.PROVED,
                justifyingSources = listOf("BiometricManager"),
                evidenceIds = evidence.filter { it.resourceType.contains("biometric.api_status") }.map { it.id },
                possibleCauses = listOf(
                    "Fingerprint HAL crashed or failed initialization",
                    "HIDL/AIDL interface mismatch between GSI Framework and Vendor HAL"
                ),
                missingData = if (halComponent?.discoveryStatus == DiscoveryStatus.INACCESSIBLE) {
                    listOf("HAL service list & vendor logs require Root or permissive dump access")
                } else emptyList(),
                recommendedSteps = listOf(
                    "Inspect HAL service state via lshal / service list",
                    "Check logcat for BiometricService / fingerprint HAL startup errors"
                )
            )
        }

        // 2. Relevant SELinux AVC denials directly observed
        val avcItems = seLinuxProbe?.items?.filter { it.key.startsWith("selinux.avc_denial") }.orEmpty()
        if (avcItems.isNotEmpty()) {
            anomalies += AnomalyRecord(
                id = "ANOM-SELINUX-AVC",
                title = "FOD-related SELinux AVC denials detected (${avcItems.size})",
                description = "Observed avc: denied entries touching fingerprint, biometric, display/HBM, or touch domains.",
                componentId = null,
                componentName = "SELinux Policy",
                severity = AnomalySeverity.HIGH,
                epistemicLevel = EpistemicLevel.PROVED,
                justifyingSources = listOf("logcat/dmesg AVC"),
                evidenceIds = evidence.filter { it.resourceType.contains("selinux.avc_denial") }.map { it.id },
                possibleCauses = listOf(
                    "Missing sepolicy rule between GSI system/system_ext domain and vendor HAL/sysfs node",
                    "Unlabeled sysfs node for HBM or fingerprint driver"
                ),
                recommendedSteps = listOf(
                    "Inspect exact scontext/tcontext/tclass in the proved AVC lines",
                    "Compare vendor vs system sepolicy expectations with a reference Custom ROM"
                )
            )
        }

        // 3. Proved error events in dumpsys or Live Trace
        val liveEvents = liveTrace?.events.orEmpty()
        val errorEvents = liveEvents.filter { it.type == TimelineEventType.ERROR || it.type == TimelineEventType.SESSION_FAILED }
        if (errorEvents.isNotEmpty()) {
            anomalies += AnomalyRecord(
                id = "ANOM-LIVE-ERRORS",
                title = "Runtime errors observed during enrollment (${errorEvents.size})",
                description = errorEvents.take(3).joinToString(" | ") { it.data },
                componentId = halComponent?.id,
                componentName = "Live Enrollment Pipeline",
                severity = AnomalySeverity.HIGH,
                epistemicLevel = EpistemicLevel.PROVED,
                justifyingSources = errorEvents.map { it.source }.distinct(),
                evidenceIds = errorEvents.map { it.evidenceId },
                associatedEventIds = errorEvents.map { it.id },
                possibleCauses = listOf(
                    "Biometric acquisition timeout or HAL error callback",
                    "Display illumination / touch synchronization failure during enrollment"
                ),
                recommendedSteps = listOf(
                    "Correlate timestamp of ERROR event against HBM_ENABLED and TOUCH_EVENT_OBSERVED"
                )
            )
        }

        // 4. HBM not observed ONLY IF HBM monitoring sources were actually accessible & enrollment occurred
        if (liveTrace != null && liveTrace.enrollmentOpened) {
            val hbmMonitored = liveTrace.observedSources.any { src ->
                src.contains("hbm", true) || src.contains("brightness", true) || src.contains("logcat", true)
            }
            val hbmSeen = liveEvents.any { it.type == TimelineEventType.HBM_ENABLED }
            val captureSeen = liveEvents.any { it.type == TimelineEventType.IMAGE_ACQUISITION }
            val touchSeen = liveEvents.any { it.type == TimelineEventType.TOUCH_EVENT_OBSERVED }

            if (hbmMonitored && touchSeen && !hbmSeen) {
                anomalies += AnomalyRecord(
                    id = "ANOM-NO-HBM-ON-TOUCH",
                    title = "Touch observed during enrollment without HBM activation",
                    description = "Monitored display/log sources recorded touch activity during enrollment, but no HBM/LHBM activation was observed.",
                    componentId = components.firstOrNull { it.role == ComponentRole.DISPLAY_HBM }?.id,
                    componentName = "Display / HBM Controller",
                    severity = AnomalySeverity.HIGH,
                    epistemicLevel = EpistemicLevel.CORRELATED,
                    justifyingSources = liveTrace.observedSources,
                    evidenceIds = liveEvents.filter { it.type == TimelineEventType.TOUCH_EVENT_OBSERVED }.map { it.evidenceId },
                    associatedEventIds = liveEvents.filter { it.type == TimelineEventType.TOUCH_EVENT_OBSERVED }.map { it.id },
                    possibleCauses = listOf(
                        "UdfpsController / Display HBM callback not wired for this vendor panel",
                        "Missing Treble/PHH display HBM sysfs toggle or property in GSI"
                    ),
                    missingData = if (!liveTrace.observedSources.any { it.startsWith("/sys/") }) {
                        listOf("Direct /sys HBM node was not writable/observable; observation relied on logcat.")
                    } else emptyList(),
                    recommendedSteps = listOf(
                        "Compare active HBM sysfs/SurfaceFlinger behavior against a working Custom ROM ZIP"
                    )
                )
            } else if (!hbmMonitored && !hbmSeen) {
                hypotheses += HypothesisRecord(
                    id = "HYP-HBM-UNMONITORED",
                    statement = "HBM illumination transitions could not be verified during enrollment.",
                    rationale = "No HBM sysfs node or accessible log stream exposed HBM state changes.",
                    confidence = ConfidenceLevel.LOW,
                    supportingEvidenceIds = emptyList(),
                    missingData = listOf("Accessible HBM sysfs node or Root logcat/dmesg access"),
                    verificationHint = "Grant Root verification or compare with Custom ROM diagnostics."
                )
            }

            if (liveTrace.enrollmentReturnedWithBiometricCheck.contains("NONE_ENROLLED") && !captureSeen) {
                hypotheses += HypothesisRecord(
                    id = "HYP-ENROLL-INCOMPLETE",
                    statement = "Enrollment session ended without enrolled fingerprint or image capture evidence.",
                    rationale = "BiometricManager still reports NONE_ENROLLED after returning from system enrollment.",
                    confidence = ConfidenceLevel.MEDIUM,
                    supportingEvidenceIds = liveEvents.map { it.evidenceId }.take(5),
                    missingData = liveTrace.inaccessibleSources,
                    verificationHint = "Check if user cancelled enrollment or if sensor failed to capture."
                )
            }
        }

        // 5. Inaccessible probes must generate explicit Hypotheses/MissingData, NEVER fake anomalies
        val inaccessibleDomains = probeResults.filter {
            it.status == DiscoveryStatus.INACCESSIBLE || it.inaccessibleReasons.isNotEmpty()
        }
        if (inaccessibleDomains.isNotEmpty()) {
            hypotheses += HypothesisRecord(
                id = "HYP-ACCESS-LIMITS",
                statement = "Partial visibility in ${inaccessibleDomains.size} probe domain(s) limits full causal proof.",
                rationale = inaccessibleDomains.joinToString("; ") { "${it.domain.name}: ${it.inaccessibleReasons.firstOrNull() ?: "restricted"}" },
                confidence = ConfidenceLevel.MEDIUM,
                supportingEvidenceIds = evidence.filter { it.epistemicLevel == EpistemicLevel.INACCESSIBLE }.map { it.id }.take(8),
                missingData = inaccessibleDomains.flatMap { it.inaccessibleReasons }.distinct(),
                verificationHint = "Enable verified Root access in Settings if available on this device, or inspect SELinux restrictions."
            )
        }

        // 6. GSI / Treble overlay hypothesis if GSI detected and no UDFPS overlay enabled
        if (environment.detectedRomType == RomType.GSI) {
            val activeUdfpsOverlays = overlayProbe?.items?.filter {
                it.value.contains("enabled=true") &&
                    (it.key.contains("udfps", true) || it.key.contains("fod", true) || it.key.contains("systemui", true))
            }.orEmpty()
            if (overlayProbe?.status == DiscoveryStatus.FOUND && activeUdfpsOverlays.isEmpty()) {
                hypotheses += HypothesisRecord(
                    id = "HYP-GSI-NO-UDFPS-RRO",
                    statement = "No active UDFPS/FOD SystemUI RRO overlay detected on this GSI.",
                    rationale = "cmd overlay list succeeded and showed zero enabled UDFPS/SystemUI overlays.",
                    confidence = ConfidenceLevel.MEDIUM,
                    supportingEvidenceIds = evidence.filter { it.resourceType.startsWith("OVERLAY") }.map { it.id }.take(5),
                    missingData = listOf("Vendor/product framework UDFPS coordinate values"),
                    verificationHint = "Compare active RRO overlays against the Custom ROM diagnostic archive."
                )
            }
        }

        // 7. Note if dumpsys fingerprint was accessible and showed non-empty config
        if (bioProbe?.status == DiscoveryStatus.INACCESSIBLE) {
            hypotheses += HypothesisRecord(
                id = "HYP-DUMPSYS-BLOCKED",
                statement = "BiometricService internal sensor dump was inaccessible without DUMP/Root privilege.",
                rationale = bioProbe.inaccessibleReasons.joinToString(),
                confidence = ConfidenceLevel.LOW,
                supportingEvidenceIds = emptyList(),
                missingData = listOf("dumpsys fingerprint sensor coordinates & HIDL/AIDL status"),
                verificationHint = "Run diagnostic with verified Root to inspect BiometricService sensor descriptors."
            )
        }

        return AnomalyAnalysisOutput(anomalies = anomalies, hypotheses = hypotheses)
    }
}
