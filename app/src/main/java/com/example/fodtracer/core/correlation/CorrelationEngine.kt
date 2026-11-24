package com.example.fodtracer.core.correlation

import com.example.fodtracer.domain.models.*

data class CorrelationOutput(
    val dependencyLinks: List<DependencyLink>,
    val correlations: List<CorrelationResult>
)

/**
 * Reconstructs expected vs. actually observed vs. unverifiable relationships across the FOD chain.
 * Never promotes an expected architectural link to an observed fact without runtime/static evidence.
 */
class CorrelationEngine {

    fun correlate(
        components: List<DiscoveredComponent>,
        evidence: List<EvidenceRecord>,
        liveTrace: LiveTraceData?
    ): CorrelationOutput {
        val sysUi = components.firstOrNull { it.role == ComponentRole.APPLICATION_SYSTEMUI }
        val bioSvc = components.firstOrNull { it.role == ComponentRole.BIOMETRIC_SERVICE }
        val hal = components.firstOrNull { it.role == ComponentRole.BIOMETRIC_HAL }
        val kernel = components.firstOrNull { it.role == ComponentRole.KERNEL_DRIVER }
        val display = components.firstOrNull { it.role == ComponentRole.DISPLAY_HBM }
        val touch = components.firstOrNull { it.role == ComponentRole.TOUCH_CONTROLLER }
        val overlays = components.firstOrNull { it.role == ComponentRole.RESOURCE_OVERLAY }

        val events = liveTrace?.events.orEmpty()
        val links = mutableListOf<DependencyLink>()
        val correlations = mutableListOf<CorrelationResult>()

        fun addLink(
            id: String,
            from: DiscoveredComponent?,
            to: DiscoveredComponent?,
            relation: String,
            observed: Boolean,
            epistemic: EpistemicLevel,
            notes: String,
            evIds: List<String>
        ) {
            if (from == null || to == null) return
            links += DependencyLink(
                id = id,
                fromComponentId = from.id,
                toComponentId = to.id,
                relationType = relation,
                expected = true,
                observed = observed,
                epistemicLevel = epistemic,
                notes = notes,
                evidenceIds = evIds
            )
        }

        // 1. Overlays -> SystemUI / Framework UDFPS configuration
        val overlayObserved = overlays?.discoveryStatus == DiscoveryStatus.FOUND && sysUi != null
        addLink(
            id = "LINK-01",
            from = overlays,
            to = sysUi,
            relation = "RRO_RESOURCE_INJECTION",
            observed = overlayObserved,
            epistemic = if (overlayObserved) EpistemicLevel.PROVED else EpistemicLevel.INACCESSIBLE,
            notes = if (overlayObserved) "Active RRO overlays discovered alongside SystemUI." else "Overlay state could not be verified.",
            evIds = overlays?.evidenceIds.orEmpty().take(5)
        )

        // 2. SystemUI -> BiometricService
        val uiToBioEvents = events.filter {
            it.type == TimelineEventType.UDFPS_UI_DISPLAYED || it.type == TimelineEventType.BIOMETRIC_SERVICE_READY
        }
        val sysUiToBioObserved = uiToBioEvents.size >= 2 ||
            (sysUi?.discoveryStatus == DiscoveryStatus.FOUND && bioSvc?.discoveryStatus == DiscoveryStatus.FOUND)
        addLink(
            id = "LINK-02",
            from = sysUi,
            to = bioSvc,
            relation = "UDFPS_PROMPT_AND_AUTH_CALLBACK",
            observed = uiToBioEvents.isNotEmpty(),
            epistemic = when {
                uiToBioEvents.size >= 2 -> EpistemicLevel.CORRELATED
                sysUiToBioObserved -> EpistemicLevel.HYPOTHESIS
                else -> EpistemicLevel.INACCESSIBLE
            },
            notes = if (uiToBioEvents.isNotEmpty()) {
                "Observed UI/BiometricService interaction during Live Trace."
            } else {
                "Static components present, runtime handoff not observed yet."
            },
            evIds = uiToBioEvents.map { it.evidenceId }
        )

        // 3. BiometricService -> Biometric HAL
        val bioToHalObserved = hal?.discoveryStatus == DiscoveryStatus.FOUND && bioSvc?.discoveryStatus == DiscoveryStatus.FOUND
        val halEvents = events.filter {
            it.type == TimelineEventType.IMAGE_ACQUISITION || it.type == TimelineEventType.BIOMETRIC_PROCESSING
        }
        addLink(
            id = "LINK-03",
            from = bioSvc,
            to = hal,
            relation = "BINDER_TO_HAL_AIDL_HIDL",
            observed = halEvents.isNotEmpty() || bioToHalObserved,
            epistemic = when {
                halEvents.isNotEmpty() -> EpistemicLevel.CORRELATED
                hal?.discoveryStatus == DiscoveryStatus.INACCESSIBLE -> EpistemicLevel.INACCESSIBLE
                bioToHalObserved -> EpistemicLevel.PROVED
                else -> EpistemicLevel.HYPOTHESIS
            },
            notes = if (hal?.discoveryStatus == DiscoveryStatus.INACCESSIBLE) {
                "HAL introspection blocked by permissions/SELinux."
            } else {
                "Framework to HAL interface alignment evaluated."
            },
            evIds = (hal?.evidenceIds.orEmpty().take(3) + halEvents.map { it.evidenceId }).distinct()
        )

        // 4. Touch -> Display HBM -> Acquisition
        val touchEvts = events.filter { it.type == TimelineEventType.TOUCH_EVENT_OBSERVED }
        val hbmEvts = events.filter { it.type == TimelineEventType.HBM_ENABLED || it.type == TimelineEventType.HBM_DISABLED }
        val acqEvts = events.filter { it.type == TimelineEventType.IMAGE_ACQUISITION }

        addLink(
            id = "LINK-04",
            from = touch,
            to = display,
            relation = "FINGER_DOWN_TO_HBM_TRIGGER",
            observed = touchEvts.isNotEmpty() && hbmEvts.isNotEmpty(),
            epistemic = when {
                touchEvts.isNotEmpty() && hbmEvts.isNotEmpty() -> EpistemicLevel.CORRELATED
                display?.discoveryStatus == DiscoveryStatus.INACCESSIBLE || touch?.discoveryStatus == DiscoveryStatus.INACCESSIBLE -> EpistemicLevel.INACCESSIBLE
                else -> EpistemicLevel.HYPOTHESIS
            },
            notes = "Touch-to-HBM illumination trigger correlation.",
            evIds = (touchEvts + hbmEvts).map { it.evidenceId }
        )

        addLink(
            id = "LINK-05",
            from = display,
            to = hal,
            relation = "HBM_ILLUMINATION_TO_SENSOR_CAPTURE",
            observed = hbmEvts.isNotEmpty() && acqEvts.isNotEmpty(),
            epistemic = when {
                hbmEvts.isNotEmpty() && acqEvts.isNotEmpty() -> EpistemicLevel.CORRELATED
                else -> EpistemicLevel.HYPOTHESIS
            },
            notes = "High Brightness Mode illumination paired with optical/sensor image capture.",
            evIds = (hbmEvts + acqEvts).map { it.evidenceId }
        )

        addLink(
            id = "LINK-06",
            from = hal,
            to = kernel,
            relation = "HAL_TO_KERNEL_DRIVER_IOCTL_SYSFS",
            observed = kernel?.discoveryStatus == DiscoveryStatus.FOUND && hal?.discoveryStatus == DiscoveryStatus.FOUND,
            epistemic = when {
                kernel?.discoveryStatus == DiscoveryStatus.INACCESSIBLE -> EpistemicLevel.INACCESSIBLE
                kernel?.discoveryStatus == DiscoveryStatus.FOUND -> EpistemicLevel.CORRELATED
                else -> EpistemicLevel.HYPOTHESIS
            },
            notes = "HAL native libraries mapped against discovered kernel driver/sysfs nodes.",
            evIds = kernel?.evidenceIds.orEmpty().take(4)
        )

        // Build CorrelationResult narratives
        correlations += CorrelationResult(
            id = "CORR-CHAIN-STACK",
            title = "Framework <-> HAL <-> Kernel Architecture Chain",
            involvedComponentIds = listOfNotNull(sysUi?.id, bioSvc?.id, hal?.id, kernel?.id),
            involvedEventIds = events.filter {
                it.type == TimelineEventType.BIOMETRIC_SERVICE_READY || it.type == TimelineEventType.BIOMETRIC_PROCESSING
            }.map { it.id },
            expectedChain = "SystemUI/UdfpsController -> BiometricService -> Biometric HAL -> Kernel Driver",
            observedBehavior = buildString {
                append("SystemUI=").append(sysUi?.discoveryStatus ?: "NONE")
                append(", BiometricService=").append(bioSvc?.discoveryStatus ?: "NONE")
                append(", HAL=").append(hal?.discoveryStatus ?: "NONE")
                append(", Kernel=").append(kernel?.discoveryStatus ?: "NONE")
            },
            verified = bioSvc?.discoveryStatus == DiscoveryStatus.FOUND && hal?.discoveryStatus == DiscoveryStatus.FOUND,
            unverifiableReason = if (hal?.discoveryStatus == DiscoveryStatus.INACCESSIBLE || kernel?.discoveryStatus == DiscoveryStatus.INACCESSIBLE) {
                "One or more low-level layers were inaccessible under current privileges/SELinux."
            } else null,
            epistemicLevel = if (hal?.discoveryStatus == DiscoveryStatus.FOUND) EpistemicLevel.CORRELATED else EpistemicLevel.INACCESSIBLE,
            evidenceIds = evidence.filter {
                it.discoveryStatus == DiscoveryStatus.FOUND &&
                    (it.resourceType.startsWith("BIOMETRIC") || it.resourceType.startsWith("HAL"))
            }.map { it.id }.take(10)
        )

        correlations += CorrelationResult(
            id = "CORR-CHAIN-OPTICAL",
            title = "Touch -> HBM/Display -> Sensor Acquisition Loop",
            involvedComponentIds = listOfNotNull(touch?.id, display?.id, hal?.id),
            involvedEventIds = (touchEvts + hbmEvts + acqEvts).map { it.id },
            expectedChain = "Touch Down -> HBM Enable -> Optical/Sensor Capture -> Processing -> HBM Disable",
            observedBehavior = if (liveTrace == null) {
                "Live Trace not executed yet; only static display/touch interfaces evaluated."
            } else {
                "Live events: touch=${touchEvts.size}, hbm=${hbmEvts.size}, capture=${acqEvts.size}"
            },
            verified = touchEvts.isNotEmpty() && hbmEvts.isNotEmpty() && acqEvts.isNotEmpty(),
            unverifiableReason = when {
                liveTrace == null -> "Phase 2 Live Tracer has not been run yet."
                liveTrace.inaccessibleSources.isNotEmpty() -> "Restricted telemetry sources: ${liveTrace.inaccessibleSources.joinToString()}"
                else -> null
            },
            epistemicLevel = when {
                touchEvts.isNotEmpty() && hbmEvts.isNotEmpty() -> EpistemicLevel.CORRELATED
                liveTrace == null -> EpistemicLevel.HYPOTHESIS
                else -> EpistemicLevel.INACCESSIBLE
            },
            evidenceIds = (touchEvts + hbmEvts + acqEvts).map { it.evidenceId }.take(12)
        )

        return CorrelationOutput(dependencyLinks = links, correlations = correlations)
    }
}
