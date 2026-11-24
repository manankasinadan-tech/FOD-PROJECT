package com.example.fodtracer.core.solution

import com.example.fodtracer.domain.models.*

/**
 * Deterministic rule-based Solution Engine classifying FOD remediation paths into:
 * - GSI_ONLY_CONFIGURATION
 * - GSI_ONLY_RUNTIME
 * - OUTSIDE_GSI_SCOPE
 *
 * Never suggests a GSI fix solely because a component is inaccessible, and never auto-modifies the system.
 */
class SolutionEngine {

    fun evaluateDiagnostic(session: DiagnosticSession): List<SolutionProposal> {
        val proposals = mutableListOf<SolutionProposal>()

        val hasOverlayHypothesis = session.hypotheses.any { it.id == "HYP-GSI-NO-UDFPS-RRO" }
        val hbmAnomaly = session.anomalies.firstOrNull { it.id == "ANOM-NO-HBM-ON-TOUCH" }
        val noFeatureAnomaly = session.anomalies.firstOrNull { it.id == "ANOM-NO-FP-FEATURE" }
        val hwUnavailableAnomaly = session.anomalies.firstOrNull { it.id == "ANOM-BIO-HW-UNAVAILABLE" }
        val avcAnomaly = session.anomalies.firstOrNull { it.id == "ANOM-SELINUX-AVC" }
        val liveErrors = session.anomalies.firstOrNull { it.id == "ANOM-LIVE-ERRORS" }

        // 1. GSI-ONLY CONFIGURATION: Missing/inactive UDFPS RRO overlay on GSI
        if (hasOverlayHypothesis) {
            proposals += SolutionProposal(
                id = "SOL-CFG-UDFPS-RRO",
                anomalyId = null,
                problemIdentified = "Active UDFPS / SystemUI RRO overlay not detected on GSI.",
                evidenceIds = session.hypotheses.first { it.id == "HYP-GSI-NO-UDFPS-RRO" }.supportingEvidenceIds,
                probableCause = "GSI lacks device-matched SystemUI/framework UDFPS coordinate and icon RRO overlay.",
                componentName = "SystemUI / Framework RRO Overlay",
                componentLocation = "/product/overlay or /system_ext/overlay",
                partitionOrigin = PartitionOrigin.PRODUCT,
                dependencies = listOf("com.android.systemui", "framework-res", "UdfpsController"),
                category = SolutionCategory.GSI_ONLY_CONFIGURATION,
                feasibility = FeasibilityLevel.POSSIBLE_WITH_CONDITIONS,
                technicalPrerequisites = listOf(
                    "Exact sensor X/Y coordinates & radius from stock/Custom ROM framework/SystemUI resources",
                    "Target package signature/overlayable alignment in GSI"
                ),
                compatibilityRisks = listOf(
                    "Incorrect sensor coordinates misalign touch/illumination mask over physical sensor"
                ),
                validationMethod = "Verify active overlay via `cmd overlay list` and re-run Phase 2 Live Tracer.",
                missingInformation = listOf("Vendor/stock UDFPS overlay XML resource values"),
                presentInGsi = false
            )
        }

        // 2. GSI-ONLY CONFIGURATION vs RUNTIME: HBM not activated on touch during enrollment
        if (hbmAnomaly != null) {
            val sysfsHbmFound = session.components.any {
                it.role == ComponentRole.DISPLAY_HBM && it.interfaces.any { path -> path.contains("hbm", true) }
            }
            proposals += SolutionProposal(
                id = "SOL-RUN-HBM-TRIGGER",
                anomalyId = hbmAnomaly.id,
                problemIdentified = hbmAnomaly.title,
                evidenceIds = hbmAnomaly.evidenceIds,
                probableCause = if (sysfsHbmFound) {
                    "Display HBM interface exists, but GSI SystemUI/UdfpsController does not trigger vendor HBM mode on finger down."
                } else {
                    "UdfpsController display illumination path does not match panel HBM/LHBM mechanism."
                },
                componentName = "UdfpsController / Display HBM Handler",
                componentLocation = "/system_ext/priv-app/SystemUI / framework",
                partitionOrigin = PartitionOrigin.SYSTEM_EXT,
                dependencies = listOf("UdfpsController", "SurfaceFlinger", "Display HAL / sysfs HBM node"),
                category = if (sysfsHbmFound) SolutionCategory.GSI_ONLY_CONFIGURATION else SolutionCategory.GSI_ONLY_RUNTIME,
                feasibility = if (sysfsHbmFound) FeasibilityLevel.POSSIBLE_WITH_CONDITIONS else FeasibilityLevel.INSUFFICIENT_EVIDENCE,
                technicalPrerequisites = listOf(
                    "Verify whether vendor HAL expects SurfaceFlinger HBM composition or sysfs HBM toggle",
                    "Confirm SELinux permissions allow system_server/SystemUI to signal HBM"
                ),
                compatibilityRisks = listOf(
                    "Improper HBM toggle can cause screen flicker, stuck max brightness, or burn-in"
                ),
                validationMethod = "Re-run Phase 2 Live Tracer and verify HBM_ENABLED immediately follows TOUCH_EVENT_OBSERVED.",
                missingInformation = hbmAnomaly.missingData,
                presentInGsi = true
            )
        }

        // 3. OUTSIDE GSI SCOPE or CONDITIONAL: SELinux AVC denials
        if (avcAnomaly != null) {
            val avcText = session.evidence
                .filter { it.id in avcAnomaly.evidenceIds }
                .joinToString("\n") { it.observedValue }
            val touchesVendorOrKernel = avcText.contains("vendor", true) ||
                avcText.contains("sysfs", true) || avcText.contains("hal_fingerprint", true)

            proposals += SolutionProposal(
                id = "SOL-SELINUX-POLICY",
                anomalyId = avcAnomaly.id,
                problemIdentified = avcAnomaly.title,
                evidenceIds = avcAnomaly.evidenceIds,
                probableCause = "SELinux blocks cross-domain access required during FOD initialization or HBM control.",
                componentName = "SELinux Policy (system/vendor split)",
                componentLocation = if (touchesVendorOrKernel) "/vendor/etc/selinux" else "/system/etc/selinux",
                partitionOrigin = if (touchesVendorOrKernel) PartitionOrigin.VENDOR else PartitionOrigin.SYSTEM,
                dependencies = listOf("Vendor sepolicy", "System/System_ext sepolicy", "HAL domain"),
                category = if (touchesVendorOrKernel) SolutionCategory.OUTSIDE_GSI_SCOPE else SolutionCategory.GSI_ONLY_CONFIGURATION,
                feasibility = if (touchesVendorOrKernel) FeasibilityLevel.NOT_SUPPORTED_BY_GSI else FeasibilityLevel.POSSIBLE_WITH_CONDITIONS,
                technicalPrerequisites = listOf(
                    "Exact scontext/tcontext/tclass extracted from AVC denials",
                    "Neverallow compatibility check against GSI sepolicy"
                ),
                compatibilityRisks = listOf(
                    "Treble sepolicy split prevents GSI from modifying vendor-owned sysfs/HAL contexts directly"
                ),
                validationMethod = "Confirm zero FOD AVC denials after targeted policy fix in permissive test build or vendor patch.",
                missingInformation = emptyList()
            )
        }

        // 4. OUTSIDE GSI SCOPE: Biometric hardware unavailable or missing feature XML
        if (hwUnavailableAnomaly != null) {
            proposals += SolutionProposal(
                id = "SOL-HAL-UNAVAILABLE",
                anomalyId = hwUnavailableAnomaly.id,
                problemIdentified = hwUnavailableAnomaly.title,
                evidenceIds = hwUnavailableAnomaly.evidenceIds,
                probableCause = "Vendor Biometric HAL failed to start, crashed, or exposes an incompatible interface.",
                componentName = "Vendor Biometric HAL",
                componentLocation = "/vendor/bin/hw or /odm/bin/hw",
                partitionOrigin = PartitionOrigin.VENDOR,
                dependencies = listOf("Vendor HAL binary", "Kernel fingerprint driver", "VINTF manifest"),
                category = SolutionCategory.OUTSIDE_GSI_SCOPE,
                feasibility = FeasibilityLevel.NOT_SUPPORTED_BY_GSI,
                technicalPrerequisites = listOf(
                    "Verify whether HAL crash is caused by missing GSI-side framework AIDL/HIDL compatibility or vendor library dependency"
                ),
                compatibilityRisks = listOf(
                    "Replacing vendor HAL binaries from a GSI is outside Treble GSI boundaries"
                ),
                validationMethod = "Check `lshal` and `dumpsys fingerprint` after verifying HAL process stability.",
                missingInformation = hwUnavailableAnomaly.missingData
            )
        }

        if (noFeatureAnomaly != null) {
            proposals += SolutionProposal(
                id = "SOL-FEATURE-FP",
                anomalyId = noFeatureAnomaly.id,
                problemIdentified = noFeatureAnomaly.title,
                evidenceIds = noFeatureAnomaly.evidenceIds,
                probableCause = "Device lacks android.hardware.fingerprint.xml or HAL disabled feature declaration.",
                componentName = "Hardware Feature Declaration",
                componentLocation = "/vendor/etc/permissions/android.hardware.fingerprint.xml",
                partitionOrigin = PartitionOrigin.VENDOR,
                dependencies = listOf("PackageManager", "Vendor permissions XML"),
                category = SolutionCategory.OUTSIDE_GSI_SCOPE,
                feasibility = FeasibilityLevel.NOT_SUPPORTED_BY_GSI,
                technicalPrerequisites = listOf("Inspect /vendor/etc/permissions/ on device"),
                compatibilityRisks = listOf("Hardware feature XML normally belongs on vendor/odm partition"),
                validationMethod = "Check PackageManager.hasSystemFeature(FEATURE_FINGERPRINT) == true.",
                missingInformation = listOf("/vendor/etc/permissions directory listing")
            )
        }

        if (liveErrors != null && proposals.none { it.anomalyId == liveErrors.id }) {
            proposals += SolutionProposal(
                id = "SOL-LIVE-ERR-INVESTIGATE",
                anomalyId = liveErrors.id,
                problemIdentified = liveErrors.title,
                evidenceIds = liveErrors.evidenceIds,
                probableCause = "Runtime error observed during Live Trace; root cause may span GSI SystemUI/Framework or Vendor HAL.",
                componentName = liveErrors.componentName,
                componentLocation = "Runtime Pipeline",
                partitionOrigin = PartitionOrigin.UNKNOWN,
                dependencies = listOf("SystemUI", "BiometricService", "Vendor HAL"),
                category = SolutionCategory.GSI_ONLY_RUNTIME,
                feasibility = FeasibilityLevel.INSUFFICIENT_EVIDENCE,
                technicalPrerequisites = listOf("Compare failing runtime error against working Custom ROM archive"),
                compatibilityRisks = listOf("Premature GSI runtime patch without isolating HAL vs Framework origin"),
                validationMethod = "Run Comparator against Custom ROM baseline.",
                missingInformation = listOf("Custom ROM baseline comparison")
            )
        }

        return proposals
    }

    fun evaluateComparison(
        report: ComparisonReport,
        romA: DiagnosticSession?,
        gsiB: DiagnosticSession?
    ): List<SolutionProposal> {
        val proposals = mutableListOf<SolutionProposal>()
        if (gsiB != null) {
            proposals += evaluateDiagnostic(gsiB)
        }

        // Add comparison-specific GSI configuration/runtime candidates backed by critical diffs
        val missingUdfpsProp = report.structuralDiffs.firstOrNull {
            it.domain == ProbeDomain.PROPERTIES &&
                it.impact == DiffImpact.CRITICAL &&
                it.classification == DiffClassification.MISSING
        }
        if (missingUdfpsProp != null) {
            proposals += SolutionProposal(
                id = "SOL-CMP-PROP-${missingUdfpsProp.key.take(24)}",
                anomalyId = null,
                problemIdentified = "FOD-related property missing in GSI: ${missingUdfpsProp.key}",
                evidenceIds = emptyList(),
                probableCause = "Custom ROM sets ${missingUdfpsProp.key}=${missingUdfpsProp.valueInRomA}, absent in GSI.",
                componentName = "System / Treble Property Configuration",
                componentLocation = "/system/build.prop or Phh/Treble runtime properties",
                partitionOrigin = PartitionOrigin.SYSTEM,
                dependencies = listOf("SystemUI", "BiometricService", "Treble properties"),
                category = SolutionCategory.GSI_ONLY_CONFIGURATION,
                feasibility = FeasibilityLevel.POSSIBLE_WITH_CONDITIONS,
                technicalPrerequisites = listOf(
                    "Verify property is read by GSI Framework/SystemUI rather than vendor HAL only",
                    "Check SELinux property_contexts permissions"
                ),
                compatibilityRisks = listOf("Proprietary ROM properties ignored by AOSP GSI without runtime support"),
                validationMethod = "Confirm target consumer in GSI codebase before configuring property.",
                missingInformation = listOf("Consumer component reading ${missingUdfpsProp.key}"),
                presentInCustomRom = true,
                presentInGsi = false
            )
        }

        val missingUiStep = report.behavioralDiffs.firstOrNull {
            it.eventType == TimelineEventType.UDFPS_UI_DISPLAYED && it.classification == DiffClassification.MISSING
        }
        if (missingUiStep != null) {
            proposals += SolutionProposal(
                id = "SOL-CMP-UDFPS-UI",
                anomalyId = null,
                problemIdentified = "UDFPS UI overlay displayed in Custom ROM (${missingUiStep.romRelativeMs}ms) but not observed in GSI.",
                evidenceIds = emptyList(),
                probableCause = "GSI SystemUI UdfpsController did not initialize or receive UDFPS sensor props from BiometricService.",
                componentName = "SystemUI UdfpsController",
                componentLocation = "/system_ext/priv-app/SystemUI",
                partitionOrigin = PartitionOrigin.SYSTEM_EXT,
                dependencies = listOf("BiometricService", "FingerprintSensorPropertiesInternal", "RRO Overlay"),
                category = SolutionCategory.GSI_ONLY_RUNTIME,
                feasibility = FeasibilityLevel.POSSIBLE_WITH_CONDITIONS,
                technicalPrerequisites = listOf(
                    "Verify sensor type reported by Biometric HAL (UDFPS_OPTICAL / UDFPS_ULTRASONIC vs REAR)",
                    "Confirm SystemUI UDFPS overlay & BiometricService sensor properties bridge"
                ),
                compatibilityRisks = listOf("Overriding sensor type in GSI runtime may break non-UDFPS devices if not gated"),
                validationMethod = "Verify UDFPS_UI_DISPLAYED event appears in Phase 2 Live Tracer.",
                missingInformation = listOf("dumpsys fingerprint sensor properties comparison"),
                presentInCustomRom = true,
                presentInGsi = false
            )
        }

        return proposals.distinctBy { it.id }
    }
}
