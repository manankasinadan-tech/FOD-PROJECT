package com.example.fodtracer.core.disasm

import com.example.fodtracer.domain.models.*

/**
 * Frida-grade read-only runtime-to-code correlator.
 * Links every observed live TimelineEvent (logcat, dmesg, binder_logs, tracefs, sysfs, dumpsys)
 * directly to the exact disassembled binaries, Dalvik/ARM64 symbols, caller->callee cross-references,
 * decoded RRO/AXML values, and /proc/<pid> kernel state captured during the session.
 */
object CodeRuntimeCorrelator {

    private val PATH_TOKEN_REGEX = Regex("(/[a-zA-Z0-9_./:-]{4,})")

    fun correlateTimelineEvents(
        events: List<TimelineEvent>,
        artifacts: List<DisassembledArtifact>,
        runtimeSnapshots: List<ProcessRuntimeSnapshot>
    ): List<TimelineEvent> {
        if (events.isEmpty() || (artifacts.isEmpty() && runtimeSnapshots.isEmpty())) return events

        return events.map { evt ->
            val refs = findCodeRefsForEvent(evt, artifacts)
            val procNote = findProcessStateForEvent(evt, runtimeSnapshots)
            evt.copy(
                codeRefs = refs,
                procStateNote = procNote
            )
        }
    }

    fun findCodeRefsForEvent(
        evt: TimelineEvent,
        artifacts: List<DisassembledArtifact>
    ): List<CodeCallRef> {
        val combined = "${evt.source} ${evt.data}"
        val combinedLower = combined.lowercase()
        val pathTokens = PATH_TOKEN_REGEX.findAll(combined).map { it.value }.toList()
        val refs = mutableListOf<CodeCallRef>()

        val eventKeywords = when (evt.type) {
            TimelineEventType.BIOMETRIC_SERVICE_READY, TimelineEventType.ENROLLMENT_OPENED ->
                listOf("biometricservice", "fingerprintservice", "startenroll", "enroll", "binder")
            TimelineEventType.UDFPS_UI_DISPLAYED ->
                listOf("udfpscontroller", "authcontroller", "showudfpsoverlay", "udfps", "overlay", "surfaceflinger")
            TimelineEventType.TOUCH_EVENT_OBSERVED ->
                listOf("onpointerdown", "fingerdown", "finger_down", "touch", "udfps", "input")
            TimelineEventType.HBM_ENABLED, TimelineEventType.HBM_DISABLED ->
                listOf("hbm", "lhbm", "dim", "illuminate", "backlight", "brightness", "drm", "composer")
            TimelineEventType.IMAGE_ACQUISITION ->
                listOf("acquire", "capture", "image", "ioctl", "goodix", "fpc", "silead", "focal", "egis", "/dev/")
            TimelineEventType.BIOMETRIC_PROCESSING, TimelineEventType.ENROLLMENT_PROGRESS, TimelineEventType.SESSION_COMPLETED ->
                listOf("enroll", "process", "template", "verify", "goodix", "fpc", "silead", "fingerprint")
            TimelineEventType.ERROR, TimelineEventType.SESSION_FAILED ->
                listOf("avc", "denied", "error", "fail", "timeout", "ioctl", "fingerprint", "hbm")
            else -> emptyList()
        }

        // Extract specific tokens present in telemetry line (e.g. UdfpsController, showUdfpsOverlay, goodix, etc.)
        val specificWords = combinedLower.split(Regex("[^a-z0-9_./:-]+"))
            .filter { it.length >= 4 && it !in NOISE_TOKENS }
            .distinct()

        for (art in artifacts) {
            if (art.kind == ArtifactKind.PROC_RUNTIME) continue
            val scoreAndMatches = scoreArtifactMatch(art, combinedLower, pathTokens, eventKeywords, specificWords)
            if (scoreAndMatches != null) {
                refs += scoreAndMatches
            }
        }

        return refs.distinctBy { "${it.artifactPath}|${it.symbolOrMethod}" }.take(6)
    }

    private fun scoreArtifactMatch(
        art: DisassembledArtifact,
        eventLower: String,
        pathTokens: List<String>,
        eventKeywords: List<String>,
        specificWords: List<String>
    ): CodeCallRef? {
        // 1. Exact path match (/sys/... or /dev/...) in strings, xrefs, or decoded resources
        val matchedPath = pathTokens.firstOrNull { pt ->
            art.extractedStrings.any { it.contains(pt, ignoreCase = true) } ||
                art.crossReferences.any { it.contains(pt, ignoreCase = true) } ||
                art.decodedResources.any { it.contains(pt, ignoreCase = true) }
        }

        // 2. Match crossReferences first (richest caller -> callee + target proof)
        val matchedXref = art.crossReferences.firstOrNull { xref ->
            val xl = xref.lowercase()
            specificWords.any { w -> xl.contains(w) } || eventKeywords.any { k -> xl.contains(k) }
        }

        // 3. Match keySymbols
        val matchedSymbol = art.keySymbols.firstOrNull { sym ->
            val sl = sym.lowercase()
            specificWords.any { w -> sl.contains(w) } || eventKeywords.any { k -> sl.contains(k) }
        }

        // 4. Match decodedResources (AXML / resources.arsc)
        val matchedRes = art.decodedResources.firstOrNull { res ->
            val rl = res.lowercase()
            specificWords.any { w -> rl.contains(w) } || eventKeywords.any { k -> rl.contains(k) }
        }

        if (matchedPath == null && matchedXref == null && matchedSymbol == null && matchedRes == null) {
            return null
        }

        val primarySymbol = when {
            matchedXref != null -> matchedXref.substringBefore(" ->").trim()
            matchedSymbol != null -> matchedSymbol
            matchedRes != null -> matchedRes.substringBefore(" =").trim()
            else -> art.name
        }

        val callerChain = buildList {
            if (matchedXref != null) {
                add(matchedXref)
            }
            if (matchedRes != null && matchedRes != matchedXref) {
                add("res: $matchedRes")
            }
        }

        val targetRes = matchedPath ?: art.extractedStrings.firstOrNull { s ->
            s.startsWith("/sys/") || s.startsWith("/dev/") || eventKeywords.any { s.contains(it, ignoreCase = true) }
        }

        return CodeCallRef(
            artifactPath = art.path,
            symbolOrMethod = primarySymbol,
            callerChain = callerChain,
            targetResource = targetRes,
            detail = matchedSymbol?.takeIf { it != primarySymbol }
        )
    }

    private fun findProcessStateForEvent(
        evt: TimelineEvent,
        snapshots: List<ProcessRuntimeSnapshot>
    ): String? {
        if (snapshots.isEmpty()) return null
        val targetSnap = when (evt.type) {
            TimelineEventType.UDFPS_UI_DISPLAYED, TimelineEventType.TOUCH_EVENT_OBSERVED ->
                snapshots.firstOrNull { it.processName.contains("systemui", true) }
                    ?: snapshots.firstOrNull { it.processName.contains("surfaceflinger", true) }
            TimelineEventType.HBM_ENABLED, TimelineEventType.HBM_DISABLED ->
                snapshots.firstOrNull {
                    it.processName.contains("surfaceflinger", true) || it.processName.contains("composer", true)
                } ?: snapshots.firstOrNull { it.processName.contains("systemui", true) }
            TimelineEventType.IMAGE_ACQUISITION, TimelineEventType.BIOMETRIC_PROCESSING,
            TimelineEventType.ENROLLMENT_PROGRESS, TimelineEventType.SESSION_COMPLETED ->
                snapshots.firstOrNull {
                    it.processName.contains("fingerprint", true) || it.processName.contains("goodix", true) ||
                        it.processName.contains("biometric", true)
                }
            else -> null
        } ?: return null

        val parts = buildList {
            add("${targetSnap.processName}(pid=${targetSnap.pid})")
            targetSnap.wchan?.takeIf { it.isNotBlank() }?.let { add("wchan=$it") }
            if (targetSnap.openFodDescriptors.isNotEmpty()) {
                add("fds=${targetSnap.openFodDescriptors.take(2).joinToString(",")}")
            }
            if (targetSnap.kernelStack.isNotEmpty()) {
                add("kstack=${targetSnap.kernelStack.take(2).joinToString("<-")}")
            }
        }
        return parts.joinToString(" | ")
    }

    private val NOISE_TOKENS = setOf(
        "main", "system", "events", "logcat", "dmesg", "true", "false",
        "info", "debug", "warn", "state", "from", "with", "null", "android"
    )
}
