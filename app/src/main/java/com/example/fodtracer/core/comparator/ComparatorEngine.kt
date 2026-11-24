package com.example.fodtracer.core.comparator

import com.example.fodtracer.domain.models.*
import kotlin.math.abs

class ComparatorEngine {

    fun compare(
        romA: DiagnosticSession,
        gsiB: DiagnosticSession
    ): ComparisonReport {
        val compatibility = evaluateCompatibility(romA, gsiB)
        val structuralDiffs = compareStructural(romA, gsiB)
        val behavioralDiffs = compareBehavioral(romA, gsiB)

        val romAnomalies = romA.anomalies
        val gsiAnomalies = gsiB.anomalies
        val romAnomalyIds = romAnomalies.map { it.id }.toSet()
        val gsiAnomalyIds = gsiAnomalies.map { it.id }.toSet()

        val onlyRom = romAnomalies.filter { it.id !in gsiAnomalyIds }
        val onlyGsi = gsiAnomalies.filter { it.id !in romAnomalyIds }

        val commonCount = countCommonComponents(romA.components, gsiB.components)
        val regressionHypotheses = buildRegressionHypotheses(
            compatibility = compatibility,
            structuralDiffs = structuralDiffs,
            behavioralDiffs = behavioralDiffs,
            onlyGsiAnomalies = onlyGsi
        )

        val itemsToExamine = buildItemsToExamine(structuralDiffs, behavioralDiffs, compatibility)
        val criticalCount = structuralDiffs.count { it.impact == DiffImpact.CRITICAL } +
            behavioralDiffs.count { it.impact == DiffImpact.CRITICAL }

        val confidence = when {
            !compatibility.isComparable -> ConfidenceLevel.LOW
            compatibility.bothHaveColdPhase && compatibility.bothHaveLivePhase -> ConfidenceLevel.HIGH
            compatibility.bothHaveColdPhase -> ConfidenceLevel.MEDIUM
            else -> ConfidenceLevel.LOW
        }

        val summary = buildString {
            append("Comparaison ${romA.label} (Ref) vs ${gsiB.label} (GSI): ")
            append("$criticalCount divergence(s) critique(s), ")
            append("${structuralDiffs.size} différence(s) structurelle(s), ")
            append("${behavioralDiffs.size} comparaison(s) comportementale(s).")
        }

        return ComparisonReport(
            comparisonId = "CMP-${System.currentTimeMillis()}",
            createdAtCivilMs = System.currentTimeMillis(),
            archiveASessionId = romA.sessionId,
            archiveALabel = romA.label,
            archiveBSessionId = gsiB.sessionId,
            archiveBLabel = gsiB.label,
            compatibility = compatibility,
            summary = summary,
            commonComponentsCount = commonCount,
            structuralDiffs = structuralDiffs,
            behavioralDiffs = behavioralDiffs,
            anomaliesOnlyInRomA = onlyRom,
            anomaliesOnlyInGsiB = onlyGsi,
            regressionHypotheses = regressionHypotheses,
            itemsToExamine = itemsToExamine,
            confidence = confidence
        )
    }

    private fun evaluateCompatibility(
        romA: DiagnosticSession,
        gsiB: DiagnosticSession
    ): ComparisonCompatibility {
        val schemaOk = romA.schemaVersion == gsiB.schemaVersion
        val sameModel = romA.environment.model.equals(gsiB.environment.model, ignoreCase = true) ||
            romA.environment.device.equals(gsiB.environment.device, ignoreCase = true)
        val sameSoc = romA.environment.socModel.equals(gsiB.environment.socModel, ignoreCase = true) ||
            romA.environment.board.equals(gsiB.environment.board, ignoreCase = true)

        val hwScore = when {
            sameModel && sameSoc -> 100
            sameModel || sameSoc -> 75
            romA.environment.manufacturer.equals(gsiB.environment.manufacturer, ignoreCase = true) -> 45
            else -> 15
        }

        val warnings = mutableListOf<String>()
        if (!schemaOk) warnings += "Schema mismatch (A=v${romA.schemaVersion}, B=v${gsiB.schemaVersion})."
        if (!sameModel) warnings += "Different device models (${romA.environment.model} vs ${gsiB.environment.model})."
        if (!sameSoc) warnings += "Different SoC/board (${romA.environment.socModel} vs ${gsiB.environment.socModel})."
        if (romA.liveTrace == null || gsiB.liveTrace == null) {
            warnings += "Live Trace missing in at least one archive; behavioral timing comparison is partial."
        }
        if (romA.environment.rootState != gsiB.environment.rootState) {
            warnings += "Privilege asymmetry (${romA.environment.rootState} vs ${gsiB.environment.rootState}) may cause INACCESSIBLE gaps."
        }

        return ComparisonCompatibility(
            isComparable = schemaOk && hwScore >= 40,
            schemaCompatible = schemaOk,
            hardwareMatchScore = hwScore,
            sameDeviceOrSoc = sameModel || sameSoc,
            androidVersionA = "${romA.environment.androidVersion} (API ${romA.environment.sdkInt})",
            androidVersionB = "${gsiB.environment.androidVersion} (API ${gsiB.environment.sdkInt})",
            bothHaveColdPhase = romA.probeResults.isNotEmpty() && gsiB.probeResults.isNotEmpty(),
            bothHaveLivePhase = romA.liveTrace != null && gsiB.liveTrace != null,
            warnings = warnings
        )
    }

    private fun compareStructural(
        romA: DiagnosticSession,
        gsiB: DiagnosticSession
    ): List<StructuralDiffItem> {
        val diffs = mutableListOf<StructuralDiffItem>()
        var idx = 0

        val domainsToCompare = listOf(
            ProbeDomain.PROPERTIES,
            ProbeDomain.BIOMETRIC,
            ProbeDomain.FRAMEWORK,
            ProbeDomain.SYSTEMUI,
            ProbeDomain.HAL,
            ProbeDomain.VENDOR,
            ProbeDomain.DISPLAY,
            ProbeDomain.KERNEL,
            ProbeDomain.TOUCH,
            ProbeDomain.OVERLAY,
            ProbeDomain.SELINUX
        )

        for (domain in domainsToCompare) {
            val probeA = romA.probeResults.firstOrNull { it.domain == domain }
            val probeB = gsiB.probeResults.firstOrNull { it.domain == domain }

            if (probeA == null && probeB == null) continue

            if (probeA?.status == DiscoveryStatus.INACCESSIBLE || probeB?.status == DiscoveryStatus.INACCESSIBLE) {
                idx += 1
                diffs += StructuralDiffItem(
                    id = "SDIFF-${idx.toString().padStart(3, '0')}",
                    domain = domain,
                    category = domain.name,
                    key = "domain.accessibility",
                    valueInRomA = probeA?.status?.name,
                    valueInGsiB = probeB?.status?.name,
                    classification = DiffClassification.INACCESSIBLE,
                    impact = DiffImpact.INFORMATIONAL,
                    rationale = "One or both archives lacked privileges to inspect ${domain.name}; cannot assert absence."
                )
            }

            val mapA = probeA?.items
                ?.filter { it.discoveryStatus == DiscoveryStatus.FOUND }
                ?.associate { normalizeKey(domain, it.key) to it.value }
                .orEmpty()
            val mapB = probeB?.items
                ?.filter { it.discoveryStatus == DiscoveryStatus.FOUND }
                ?.associate { normalizeKey(domain, it.key) to it.value }
                .orEmpty()

            val allKeys = (mapA.keys + mapB.keys).distinct().take(60)
            for (k in allKeys) {
                val valA = mapA[k]
                val valB = mapB[k]
                if (valA == valB) continue

                idx += 1
                val classification = when {
                    valA != null && valB == null -> {
                        if (probeB?.status == DiscoveryStatus.INACCESSIBLE || probeB?.status == DiscoveryStatus.PARTIAL) {
                            DiffClassification.PARTIAL
                        } else {
                            DiffClassification.MISSING
                        }
                    }
                    valA == null && valB != null -> DiffClassification.DIFFERENT
                    else -> DiffClassification.DIFFERENT
                }

                val impact = classifyStructuralImpact(domain, k, valA, valB, classification)
                diffs += StructuralDiffItem(
                    id = "SDIFF-${idx.toString().padStart(3, '0')}",
                    domain = domain,
                    category = domain.name,
                    key = k,
                    valueInRomA = valA,
                    valueInGsiB = valB,
                    classification = classification,
                    impact = impact,
                    rationale = buildStructuralRationale(domain, k, classification, impact)
                )
            }
        }
        return diffs.sortedByDescending { it.impact == DiffImpact.CRITICAL }
    }

    private fun normalizeKey(domain: ProbeDomain, rawKey: String): String {
        return when (domain) {
            ProbeDomain.PROPERTIES -> rawKey
            else -> rawKey.substringBeforeLast('.', rawKey)
        }
    }

    private fun classifyStructuralImpact(
        domain: ProbeDomain,
        key: String,
        valA: String?,
        valB: String?,
        classification: DiffClassification
    ): DiffImpact {
        val lower = key.lowercase()
        if (lower.contains("ro.build.") || lower.contains("security_patch") || lower.contains("display.id")) {
            return DiffImpact.BENIGN
        }
        if (domain == ProbeDomain.OVERLAY && (lower.contains("udfps") || lower.contains("fod") || lower.contains("systemui"))) {
            return if (classification == DiffClassification.MISSING || valA != valB) DiffImpact.CRITICAL else DiffImpact.BENIGN
        }
        if (domain == ProbeDomain.BIOMETRIC || domain == ProbeDomain.HAL || domain == ProbeDomain.DISPLAY) {
            if (lower.contains("hbm") || lower.contains("lhbm") || lower.contains("udfps") ||
                lower.contains("fod") || lower.contains("sensor") || lower.contains("api_status")
            ) {
                return DiffImpact.CRITICAL
            }
        }
        if (domain == ProbeDomain.SELINUX && lower.contains("avc_denial")) {
            return DiffImpact.CRITICAL
        }
        if (domain == ProbeDomain.PROPERTIES && (lower.contains("fp") || lower.contains("udfps") || lower.contains("fod") || lower.contains("hbm"))) {
            return DiffImpact.CRITICAL
        }
        return DiffImpact.INFORMATIONAL
    }

    private fun buildStructuralRationale(
        domain: ProbeDomain,
        key: String,
        classification: DiffClassification,
        impact: DiffImpact
    ): String = when {
        impact == DiffImpact.BENIGN -> "Expected build/ROM metadata variation ($key)."
        classification == DiffClassification.MISSING -> "$key observed in Custom ROM reference but missing in GSI ($domain)."
        classification == DiffClassification.PARTIAL -> "$key missing in GSI output, though probe was partial/restricted."
        impact == DiffImpact.CRITICAL -> "FOD-relevant divergence on $key within ${domain.name}; candidate for verification."
        else -> "Observed difference in ${domain.name} ($key); verify functional relevance."
    }

    private fun compareBehavioral(
        romA: DiagnosticSession,
        gsiB: DiagnosticSession
    ): List<BehavioralDiffItem> {
        val liveA = romA.liveTrace
        val liveB = gsiB.liveTrace
        if (liveA == null || liveB == null) {
            return listOf(
                BehavioralDiffItem(
                    id = "BDIFF-000",
                    stepName = "Live Trace Availability",
                    eventType = null,
                    romRelativeMs = liveA?.durationMs,
                    gsiRelativeMs = liveB?.durationMs,
                    latencyDeltaMs = null,
                    classification = DiffClassification.INCOMPATIBLE,
                    impact = DiffImpact.INFORMATIONAL,
                    observation = "Behavioral timeline comparison incomplete because Phase 2 Live Trace was not captured in both archives."
                )
            )
        }

        val steps = listOf(
            TimelineEventType.ENROLLMENT_OPENED,
            TimelineEventType.BIOMETRIC_SERVICE_READY,
            TimelineEventType.UDFPS_UI_DISPLAYED,
            TimelineEventType.TOUCH_EVENT_OBSERVED,
            TimelineEventType.HBM_ENABLED,
            TimelineEventType.IMAGE_ACQUISITION,
            TimelineEventType.BIOMETRIC_PROCESSING,
            TimelineEventType.ENROLLMENT_PROGRESS,
            TimelineEventType.HBM_DISABLED,
            TimelineEventType.SESSION_COMPLETED
        )

        return steps.mapIndexed { idx, stepType ->
            val evtA = liveA.events.firstOrNull { it.type == stepType }
            val evtB = liveB.events.firstOrNull { it.type == stepType }
            val tA = evtA?.relativeMs
            val tB = evtB?.relativeMs
            val delta = if (tA != null && tB != null) tB - tA else null

            val classification = when {
                evtA != null && evtB != null -> {
                    if (delta != null && abs(delta) > 750L) DiffClassification.DIFFERENT else DiffClassification.IDENTICAL
                }
                evtA != null && evtB == null -> {
                    if (liveB.inaccessibleSources.isNotEmpty()) DiffClassification.PARTIAL else DiffClassification.MISSING
                }
                evtA == null && evtB != null -> DiffClassification.DIFFERENT
                else -> DiffClassification.INACCESSIBLE
            }

            val impact = when (classification) {
                DiffClassification.MISSING -> {
                    if (stepType in listOf(
                            TimelineEventType.UDFPS_UI_DISPLAYED,
                            TimelineEventType.TOUCH_EVENT_OBSERVED,
                            TimelineEventType.HBM_ENABLED,
                            TimelineEventType.IMAGE_ACQUISITION
                        )
                    ) DiffImpact.CRITICAL else DiffImpact.INFORMATIONAL
                }
                DiffClassification.DIFFERENT -> {
                    if (delta != null && abs(delta) > 1500L) DiffImpact.CRITICAL else DiffImpact.BENIGN
                }
                else -> DiffImpact.BENIGN
            }

            val note = when (classification) {
                DiffClassification.IDENTICAL -> "Both systems reached ${stepType.name} with comparable timing."
                DiffClassification.MISSING -> "${stepType.name} occurred in Custom ROM (${tA}ms) but was absent in GSI."
                DiffClassification.PARTIAL -> "${stepType.name} absent in GSI, but GSI had inaccessible live sources."
                DiffClassification.DIFFERENT -> "Timing/state divergence (${tA ?: "?"}ms vs ${tB ?: "?"}ms)."
                else -> "Neither archive recorded ${stepType.name}."
            }

            BehavioralDiffItem(
                id = "BDIFF-${(idx + 1).toString().padStart(3, '0')}",
                stepName = stepType.name,
                eventType = stepType,
                romRelativeMs = tA,
                gsiRelativeMs = tB,
                latencyDeltaMs = delta,
                classification = classification,
                impact = impact,
                observation = note
            )
        }
    }

    private fun countCommonComponents(
        a: List<DiscoveredComponent>,
        b: List<DiscoveredComponent>
    ): Int {
        val rolesB = b.filter { it.discoveryStatus == DiscoveryStatus.FOUND }.map { it.role }.toSet()
        return a.count { it.discoveryStatus == DiscoveryStatus.FOUND && it.role in rolesB }
    }

    private fun buildRegressionHypotheses(
        compatibility: ComparisonCompatibility,
        structuralDiffs: List<StructuralDiffItem>,
        behavioralDiffs: List<BehavioralDiffItem>,
        onlyGsiAnomalies: List<AnomalyRecord>
    ): List<HypothesisRecord> {
        val hyps = mutableListOf<HypothesisRecord>()

        val missingOverlay = structuralDiffs.any {
            it.domain == ProbeDomain.OVERLAY && it.classification == DiffClassification.MISSING
        }
        if (missingOverlay) {
            hyps += HypothesisRecord(
                id = "CMP-HYP-OVERLAY",
                statement = "Missing UDFPS/SystemUI RRO overlay in GSI compared to Custom ROM.",
                rationale = "Custom ROM exposed active UDFPS/SystemUI overlay entries absent in GSI.",
                confidence = ConfidenceLevel.MEDIUM,
                supportingEvidenceIds = emptyList(),
                missingData = listOf("Overlay APK resource XML inspection"),
                verificationHint = "Verify whether GSI includes a Treble/vendor-matched UDFPS RRO."
            )
        }

        val missingHbm = behavioralDiffs.any {
            it.eventType == TimelineEventType.HBM_ENABLED && it.classification == DiffClassification.MISSING
        }
        if (missingHbm) {
            hyps += HypothesisRecord(
                id = "CMP-HYP-HBM",
                statement = "HBM activation observed in Custom ROM failed to trigger in GSI.",
                rationale = "Custom ROM triggered HBM_ENABLED during enrollment whereas GSI did not.",
                confidence = if (compatibility.bothHaveLivePhase) ConfidenceLevel.HIGH else ConfidenceLevel.LOW,
                supportingEvidenceIds = emptyList(),
                missingData = listOf("SurfaceFlinger / vendor HBM sysfs write trace"),
                verificationHint = "Check PHH/Treble display HBM configuration or Framework UDFPS display handler."
            )
        }

        if (onlyGsiAnomalies.isNotEmpty()) {
            hyps += HypothesisRecord(
                id = "CMP-HYP-ANOM",
                statement = "${onlyGsiAnomalies.size} anomaly(ies) present exclusively in the GSI diagnostic.",
                rationale = onlyGsiAnomalies.joinToString("; ") { it.title },
                confidence = ConfidenceLevel.HIGH,
                supportingEvidenceIds = onlyGsiAnomalies.flatMap { it.evidenceIds }.distinct(),
                missingData = onlyGsiAnomalies.flatMap { it.missingData }.distinct(),
                verificationHint = "Cross-reference with GSI-ONLY CONFIGURATION vs RUNTIME solution rules."
            )
        }

        return hyps
    }

    private fun buildItemsToExamine(
        structuralDiffs: List<StructuralDiffItem>,
        behavioralDiffs: List<BehavioralDiffItem>,
        compatibility: ComparisonCompatibility
    ): List<String> {
        val items = mutableListOf<String>()
        items += structuralDiffs.filter { it.impact == DiffImpact.CRITICAL }
            .take(6)
            .map { "[${it.domain.name}] ${it.key}: ${it.classification.name}" }
        items += behavioralDiffs.filter { it.impact == DiffImpact.CRITICAL }
            .take(5)
            .map { "[TIMELINE] ${it.stepName}: ${it.observation}" }
        if (compatibility.warnings.isNotEmpty()) {
            items += compatibility.warnings.map { "[COMPAT] $it" }
        }
        return items.distinct()
    }
}
