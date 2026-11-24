package com.example.fodtracer.core.disasm

import com.example.fodtracer.domain.models.*

/**
 * Reconstructs the complete 6-stage FOD/UDFPS mechanism chain by fusing static disassembly
 * (DEX, ELF, RRO, init.rc, VINTF) with live enrollment proofs (logcat, dmesg, sysfs transitions,
 * SurfaceFlinger composition, dumpsys fingerprint, and /proc/<pid>/fd & maps).
 * Never presents unverified or inaccessible steps as proved facts.
 */
object FodLogicReconstructor {

    fun reconstruct(
        probeResults: List<ProbeResult>,
        artifacts: List<DisassembledArtifact>,
        liveTrace: LiveTraceData?
    ): List<FodMechanismStep> {
        val events = liveTrace?.events.orEmpty()
        val snapshots = liveTrace?.runtimeSnapshots.orEmpty()
        val steps = mutableListOf<FodMechanismStep>()

        val dexArtifacts = artifacts.filter { it.kind == ArtifactKind.APK_DEX }
        val rroArtifacts = artifacts.filter { it.kind == ArtifactKind.RRO_OVERLAY }
        val elfArtifacts = artifacts.filter { it.kind == ArtifactKind.ELF_BINARY || it.kind == ArtifactKind.ELF_SHARED_LIB }
        val rcArtifacts = artifacts.filter { it.kind == ArtifactKind.INIT_RC || it.kind == ArtifactKind.VINTF_XML }

        // Stage 1: Framework Biometric Prompt & BiometricService
        val bioReadyEvts = events.filter {
            it.type == TimelineEventType.ENROLLMENT_OPENED || it.type == TimelineEventType.BIOMETRIC_SERVICE_READY
        }
        val fwSymbols = dexArtifacts
            .flatMap { it.keySymbols }
            .filter { it.contains("Biometric", true) || it.contains("Fingerprint", true) }
            .distinct().take(10)
        val bioProbe = probeResults.firstOrNull { it.domain == ProbeDomain.BIOMETRIC }
        val bioBlocked = bioProbe?.status == DiscoveryStatus.INACCESSIBLE

        steps += FodMechanismStep(
            order = 1,
            stageName = "1. Framework Trigger & BiometricService",
            componentName = "BiometricService / FingerprintService",
            mechanismSummary = if (bioReadyEvts.isNotEmpty()) {
                "System enrollment initiated BiometricService/FingerprintService callback chain."
            } else {
                "Static Framework Biometric/Fingerprint classes inspected; awaiting live enrollment trigger."
            },
            involvedFiles = dexArtifacts.filter { it.path.contains("services") || it.path.contains("framework") }
                .map { it.path }.ifEmpty { listOf("Binder: biometric / fingerprint") },
            observedSymbolsOrCalls = fwSymbols,
            runtimeProofs = bioReadyEvts.map { "+${it.relativeMs}ms ${it.data.take(100)}" } +
                listOfNotNull(liveTrace?.dumpsysFingerprintDelta),
            epistemicLevel = when {
                bioReadyEvts.isNotEmpty() -> EpistemicLevel.PROVED
                fwSymbols.isNotEmpty() -> EpistemicLevel.CORRELATED
                bioBlocked -> EpistemicLevel.INACCESSIBLE
                else -> EpistemicLevel.HYPOTHESIS
            },
            verifiedInLiveTrace = bioReadyEvts.isNotEmpty(),
            missingInfo = if (bioBlocked) "dumpsys fingerprint/biometric required Root privilege" else null
        )

        // Stage 2: SystemUI UDFPS Overlay & RRO Sensor Geometry
        val uiEvts = events.filter { it.type == TimelineEventType.UDFPS_UI_DISPLAYED }
        val sysUiSymbols = dexArtifacts
            .filter { it.path.contains("SystemUI", true) }
            .flatMap { it.keySymbols }
            .filter { it.contains("Udfps", true) || it.contains("AuthController", true) }
            .distinct().take(12)
        val sfHasUdfps = liveTrace?.surfaceFlingerSnapshot?.contains("udfps", ignoreCase = true) == true ||
            liveTrace?.surfaceFlingerSnapshot?.contains("biometric", ignoreCase = true) == true

        steps += FodMechanismStep(
            order = 2,
            stageName = "2. SystemUI UDFPS Overlay & Geometry",
            componentName = "UdfpsController + RRO Overlays",
            mechanismSummary = when {
                uiEvts.isNotEmpty() || sfHasUdfps -> "SystemUI mounted UDFPS sensor overlay and aligned SurfaceFlinger layer."
                rroArtifacts.isNotEmpty() || sysUiSymbols.isNotEmpty() -> "SystemUI/RRO UDFPS classes & resources discovered statically."
                else -> "SystemUI UDFPS overlay activity not yet observed."
            },
            involvedFiles = (dexArtifacts.filter { it.path.contains("SystemUI", true) }.map { it.path } +
                rroArtifacts.map { it.path }).distinct(),
            observedSymbolsOrCalls = sysUiSymbols + rroArtifacts.flatMap { it.extractedStrings }.take(8),
            runtimeProofs = uiEvts.map { "+${it.relativeMs}ms ${it.data.take(100)}" } +
                listOfNotNull(liveTrace?.surfaceFlingerSnapshot?.take(180)),
            epistemicLevel = when {
                uiEvts.isNotEmpty() || sfHasUdfps -> EpistemicLevel.PROVED
                sysUiSymbols.isNotEmpty() || rroArtifacts.isNotEmpty() -> EpistemicLevel.CORRELATED
                else -> EpistemicLevel.HYPOTHESIS
            },
            verifiedInLiveTrace = uiEvts.isNotEmpty() || sfHasUdfps,
            missingInfo = if (uiEvts.isEmpty() && !sfHasUdfps) "Live enrollment UI layer not observed during trace" else null
        )

        // Stage 3: Touch Controller -> FOD Finger Down Coordination
        val touchEvts = events.filter { it.type == TimelineEventType.TOUCH_EVENT_OBSERVED }
        val touchProbe = probeResults.firstOrNull { it.domain == ProbeDomain.TOUCH }
        val touchNodes = touchProbe?.items?.filter { it.discoveryStatus == DiscoveryStatus.FOUND }?.map { it.location }.orEmpty()

        steps += FodMechanismStep(
            order = 3,
            stageName = "3. Touch Controller -> Finger-Down Dispatch",
            componentName = "Touch Driver / InputDispatcher / UdfpsController",
            mechanismSummary = if (touchEvts.isNotEmpty()) {
                "Finger-down touch signal observed and routed to FOD pipeline."
            } else {
                "Touch controller nodes mapped; finger-down transition not observed in live buffer."
            },
            involvedFiles = touchNodes.distinct().take(6),
            observedSymbolsOrCalls = (sysUiSymbols.filter { it.contains("Pointer", true) || it.contains("Finger", true) } +
                elfArtifacts.flatMap { it.keySymbols }.filter { it.contains("finger", true) || it.contains("touch", true) }).distinct().take(8),
            runtimeProofs = touchEvts.map { "+${it.relativeMs}ms ${it.data.take(100)}" },
            epistemicLevel = when {
                touchEvts.isNotEmpty() -> EpistemicLevel.PROVED
                touchProbe?.status == DiscoveryStatus.INACCESSIBLE -> EpistemicLevel.INACCESSIBLE
                touchNodes.isNotEmpty() -> EpistemicLevel.CORRELATED
                else -> EpistemicLevel.HYPOTHESIS
            },
            verifiedInLiveTrace = touchEvts.isNotEmpty(),
            missingInfo = if (touchEvts.isEmpty()) "No TOUCH_EVENT_OBSERVED captured during enrollment" else null
        )

        // Stage 4: Display Illumination (HBM / LHBM / DimLayer)
        val hbmEvts = events.filter { it.type == TimelineEventType.HBM_ENABLED || it.type == TimelineEventType.HBM_DISABLED }
        val dispProbe = probeResults.firstOrNull { it.domain == ProbeDomain.DISPLAY }
        val hbmSysfs = dispProbe?.items?.filter {
            it.location.startsWith("/sys/") && (it.location.contains("hbm", true) || it.location.contains("brightness", true) || it.location.contains("dim", true))
        }?.map { it.location }.orEmpty()
        val hbmElfStrings = elfArtifacts.flatMap { it.extractedStrings }.filter {
            it.contains("hbm", true) || it.contains("drm", true) || it.contains("dim", true) || it.contains("/sys/class/", true)
        }.distinct().take(8)

        steps += FodMechanismStep(
            order = 4,
            stageName = "4. Display Illumination (HBM / LHBM)",
            componentName = "Display HAL / SurfaceFlinger / DRM HBM",
            mechanismSummary = when {
                hbmEvts.isNotEmpty() -> "High Brightness Mode / LHBM activation observed directly during touch."
                hbmSysfs.isNotEmpty() || hbmElfStrings.isNotEmpty() -> "Display HBM interfaces discovered statically; live HBM transition not observed."
                else -> "HBM illumination mechanism remains unverified."
            },
            involvedFiles = (hbmSysfs + elfArtifacts.filter { it.path.contains("display", true) || it.path.contains("composer", true) }.map { it.path }).distinct().take(6),
            observedSymbolsOrCalls = hbmElfStrings + elfArtifacts.flatMap { it.keySymbols }.filter { it.contains("hbm", true) || it.contains("dim", true) }.take(6),
            runtimeProofs = hbmEvts.map { "+${it.relativeMs}ms ${it.data.take(100)}" },
            epistemicLevel = when {
                hbmEvts.isNotEmpty() -> EpistemicLevel.PROVED
                dispProbe?.status == DiscoveryStatus.INACCESSIBLE -> EpistemicLevel.INACCESSIBLE
                hbmSysfs.isNotEmpty() || hbmElfStrings.isNotEmpty() -> EpistemicLevel.CORRELATED
                else -> EpistemicLevel.HYPOTHESIS
            },
            verifiedInLiveTrace = hbmEvts.isNotEmpty(),
            missingInfo = if (hbmEvts.isEmpty()) "No HBM_ENABLED transition observed (check sysfs/dmesg/SurfaceFlinger permissions)" else null
        )

        // Stage 5: Biometric HAL Native Pipeline & Kernel Driver (/proc/<pid>/fd + ELF disassembly)
        val halSnapshots = snapshots.filter { it.processName.contains("finger", true) || it.processName.contains("biometric", true) }
        val openDevs = halSnapshots.flatMap { it.openFodDescriptors }.distinct().take(10)
        val loadedLibs = halSnapshots.flatMap { it.loadedFodLibraries }.distinct().take(10)
        val halElfs = elfArtifacts.filter {
            it.path.contains("finger", true) || it.path.contains("goodix", true) || it.path.contains("fpc", true) || it.path.contains("biometric", true)
        }
        val halFiles = (halElfs.map { it.path } + rcArtifacts.map { it.path } + loadedLibs).distinct().take(10)
        val halSyms = halElfs.flatMap { it.keySymbols }.distinct().take(12)

        steps += FodMechanismStep(
            order = 5,
            stageName = "5. Vendor Biometric HAL -> Kernel Driver",
            componentName = "Fingerprint HAL (.so / ioctl /dev/*)",
            mechanismSummary = when {
                openDevs.isNotEmpty() -> "Live HAL process holds open kernel device/sysfs handles and loaded vendor libraries."
                halElfs.isNotEmpty() -> "Vendor HAL binaries & ELF symbols disassembled (${halElfs.size} binaries)."
                else -> "Vendor HAL binaries or /proc/<pid>/fd inaccessible."
            },
            involvedFiles = halFiles,
            observedSymbolsOrCalls = halSyms + halElfs.flatMap { it.neededLibraries }.distinct().take(6),
            runtimeProofs = openDevs,
            epistemicLevel = when {
                openDevs.isNotEmpty() || (halElfs.isNotEmpty() && loadedLibs.isNotEmpty()) -> EpistemicLevel.PROVED
                halElfs.isNotEmpty() -> EpistemicLevel.CORRELATED
                probeResults.firstOrNull { it.domain == ProbeDomain.HAL }?.status == DiscoveryStatus.INACCESSIBLE -> EpistemicLevel.INACCESSIBLE
                else -> EpistemicLevel.HYPOTHESIS
            },
            verifiedInLiveTrace = openDevs.isNotEmpty() || loadedLibs.isNotEmpty(),
            missingInfo = if (openDevs.isEmpty()) "HAL /proc/<pid>/fd descriptors require verified Root access" else null
        )

        // Stage 6: Image Acquisition, Template Processing & Enrollment Result
        val acqAndProcEvts = events.filter {
            it.type == TimelineEventType.IMAGE_ACQUISITION ||
                it.type == TimelineEventType.BIOMETRIC_PROCESSING ||
                it.type == TimelineEventType.ENROLLMENT_PROGRESS ||
                it.type == TimelineEventType.SESSION_COMPLETED ||
                it.type == TimelineEventType.SESSION_FAILED ||
                it.type == TimelineEventType.ERROR
        }

        steps += FodMechanismStep(
            order = 6,
            stageName = "6. Capture, Processing & Enrollment Outcome",
            componentName = "HAL Capture -> BiometricManager State",
            mechanismSummary = when {
                acqAndProcEvts.any { it.type == TimelineEventType.SESSION_COMPLETED } -> "Enrollment pipeline completed and validated fingerprint template."
                acqAndProcEvts.any { it.type == TimelineEventType.ERROR || it.type == TimelineEventType.SESSION_FAILED } -> "Enrollment pipeline encountered an observed runtime error or failure."
                acqAndProcEvts.isNotEmpty() -> "Partial capture/processing callbacks observed."
                else -> "Post-return BiometricManager state: ${liveTrace?.enrollmentReturnedWithBiometricCheck ?: "not checked"}."
            },
            involvedFiles = halElfs.map { it.path }.take(4),
            observedSymbolsOrCalls = acqAndProcEvts.map { "${it.type.name} (${it.source})" }.distinct(),
            runtimeProofs = acqAndProcEvts.take(8).map { "+${it.relativeMs}ms ${it.data.take(100)}" },
            epistemicLevel = when {
                acqAndProcEvts.isNotEmpty() -> EpistemicLevel.PROVED
                liveTrace != null -> EpistemicLevel.CORRELATED
                else -> EpistemicLevel.HYPOTHESIS
            },
            verifiedInLiveTrace = acqAndProcEvts.isNotEmpty(),
            missingInfo = if (liveTrace == null) "Phase 2 Live Trace not executed yet" else null
        )

        return steps
    }
}
