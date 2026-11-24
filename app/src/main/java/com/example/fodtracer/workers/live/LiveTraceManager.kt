package com.example.fodtracer.workers.live

import android.content.Context
import com.example.fodtracer.domain.interfaces.*
import com.example.fodtracer.domain.models.*
import com.example.fodtracer.system.biometrics.AndroidBiometricInspector
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.atomic.AtomicInteger

data class LiveTraceProgress(
    val isRunning: Boolean = false,
    val elapsedMs: Long = 0L,
    val eventCount: Int = 0,
    val observedSources: List<String> = emptyList(),
    val inaccessibleSources: List<String> = emptyList(),
    val latestEventSummary: String? = null
)

/**
 * Pure parser and state-transition recognizer for live FOD telemetry,
 * reusable across ForegroundService runtime and unit tests.
 */
object LiveEventNormalizer {

    fun isFodRelevantLog(line: String): Boolean {
        val l = line.lowercase()
        return l.contains("udfps") || l.contains("fingerprint") || l.contains("biometric") ||
            l.contains("fod") || l.contains("hbm") || l.contains("lhbm") ||
            l.contains("goodix") || l.contains("fpc") || l.contains("silead") ||
            l.contains("focal") || l.contains("egis") || l.contains("qbt") ||
            l.contains("authcontroller") || l.contains("finger_down") || l.contains("fingerdown")
    }

    fun classifyLogLine(
        line: String,
        source: String,
        sessionStartNanos: Long,
        monotonicNanos: Long,
        civilMs: Long,
        eventCounter: AtomicInteger,
        accessLevel: AccessLevel
    ): Pair<TimelineEvent, EvidenceRecord>? {
        val lower = line.lowercase()
        val matchedType: Pair<TimelineEventType, ConfidenceLevel>? = when {
            (lower.contains("hbm") || lower.contains("lhbm")) &&
                (lower.contains("enable") || lower.contains("on") || lower.contains("enter") ||
                    lower.contains("= 1") || lower.contains("=1") || lower.contains("true") ||
                    lower.contains("set_hbm 1") || lower.contains("activate")) ->
                TimelineEventType.HBM_ENABLED to ConfidenceLevel.HIGH

            (lower.contains("hbm") || lower.contains("lhbm")) &&
                (lower.contains("disable") || lower.contains("off") || lower.contains("exit") ||
                    lower.contains("= 0") || lower.contains("=0") || lower.contains("false") ||
                    lower.contains("set_hbm 0") || lower.contains("deactivate")) ->
                TimelineEventType.HBM_DISABLED to ConfidenceLevel.HIGH

            lower.contains("udfps") &&
                (lower.contains("show") || lower.contains("overlay") || lower.contains("onacquired") ||
                    lower.contains("display") || lower.contains("mount") || lower.contains("hide") ||
                    lower.contains("illuminate")) ->
                TimelineEventType.UDFPS_UI_DISPLAYED to ConfidenceLevel.HIGH

            lower.contains("onpointerdown") || lower.contains("fingerdown") ||
                lower.contains("finger_down") || lower.contains("touch_down") ||
                lower.contains("fod_touch") || lower.contains("fod_press") ||
                (lower.contains("touch") && lower.contains("fod")) ->
                TimelineEventType.TOUCH_EVENT_OBSERVED to ConfidenceLevel.HIGH

            lower.contains("enroll") &&
                (lower.contains("complete") || lower.contains("success") || lower.contains("finished") ||
                    lower.contains("remaining=0") || lower.contains("remaining = 0")) ->
                TimelineEventType.SESSION_COMPLETED to ConfidenceLevel.HIGH

            lower.contains("enroll") &&
                (lower.contains("remaining") || lower.contains("progress") || lower.contains("step")) ->
                TimelineEventType.ENROLLMENT_PROGRESS to ConfidenceLevel.HIGH

            lower.contains("capture") || lower.contains("acquire") ||
                ((lower.contains("image") || lower.contains("ioctl") || lower.contains("spi")) &&
                    (lower.contains("fp") || lower.contains("goodix") || lower.contains("fpc") ||
                        lower.contains("silead") || lower.contains("biometric") || lower.contains("fingerprint"))) ->
                TimelineEventType.IMAGE_ACQUISITION to ConfidenceLevel.MEDIUM

            lower.contains("biometric") &&
                (lower.contains("ready") || lower.contains("enroll(") || lower.contains("startenroll") ||
                    lower.contains("client") || lower.contains("authsession")) ->
                TimelineEventType.BIOMETRIC_SERVICE_READY to ConfidenceLevel.MEDIUM

            lower.contains("process") || lower.contains("template") ||
                ((lower.contains("goodix") || lower.contains("fpc") || lower.contains("silead") || lower.contains("fingerprint")) &&
                    (lower.contains("algo") || lower.contains("extract") || lower.contains("verify"))) ->
                TimelineEventType.BIOMETRIC_PROCESSING to ConfidenceLevel.MEDIUM

            lower.contains("error") || lower.contains("timeout") || lower.contains("failed") ||
                lower.contains("avc: denied") ->
                if (lower.contains("enroll") && lower.contains("fail")) {
                    TimelineEventType.SESSION_FAILED to ConfidenceLevel.HIGH
                } else {
                    TimelineEventType.ERROR to ConfidenceLevel.MEDIUM
                }

            else -> null
        }

        val (type, confidence) = matchedType ?: return null
        val seq = eventCounter.incrementAndGet()
        val evId = "EV-LIVE-${seq.toString().padStart(4, '0')}"
        val evtId = "EVT-LIVE-${seq.toString().padStart(4, '0')}"
        val relMs = ((monotonicNanos - sessionStartNanos) / 1_000_000L).coerceAtLeast(0L)

        val evidence = EvidenceRecord(
            id = evId,
            source = source,
            resourceType = "LIVE_TELEMETRY:${type.name}",
            observedValue = line.trim().take(280),
            civilTimestampMs = civilMs,
            monotonicNanos = monotonicNanos,
            collectionMethod = "LiveTracer:$source",
            accessLevel = accessLevel,
            executionResult = "OBSERVED",
            discoveryStatus = DiscoveryStatus.FOUND,
            epistemicLevel = EpistemicLevel.PROVED
        )

        val event = TimelineEvent(
            id = evtId,
            type = type,
            monotonicNanos = monotonicNanos,
            relativeMs = relMs,
            civilTimestampMs = civilMs,
            source = source,
            data = line.trim().take(240),
            evidenceId = evId,
            confidence = confidence,
            observationType = ObservationType.DIRECT_OBSERVATION
        )
        return event to evidence
    }
}

class LiveTraceCoordinator(
    private val context: Context,
    private val shellExecutor: ShellExecutor,
    private val privilegeManager: PrivilegeManager
) {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var collectorJob: Job? = null

    private val _progress = MutableStateFlow(LiveTraceProgress())
    val progress: StateFlow<LiveTraceProgress> = _progress.asStateFlow()

    private val eventBuffer = ArrayDeque<TimelineEvent>(MAX_TIMELINE_EVENTS)
    private val evidenceBuffer = ArrayDeque<EvidenceRecord>(MAX_TIMELINE_EVENTS)
    private val observedSources = linkedSetOf<String>()
    private val inaccessibleSources = linkedSetOf<String>()
    private val seenLogLines = HashSet<String>()
    private val seenDmesgLines = HashSet<String>()
    private val lastSysfsValues = HashMap<String, String>()
    private val capturedSnapshots = linkedMapOf<Int, ProcessRuntimeSnapshot>()
    private val eventCounter = AtomicInteger(0)

    private var sessionStartNanos: Long = 0L
    private var bufferTruncated = false
    private var targetSysfsPaths: List<SafeSystemPath> = emptyList()
    private var enrollmentOpenedMarked = false
    private var lastAllowRoot = false
    private var initialFingerprintDump: String? = null
    private var latestFingerprintDump: String? = null
    private var latestSurfaceFlingerSnippet: String? = null
    private var pollTick = 0

    fun startSession(coldSession: DiagnosticSession?) {
        stopInternal()
        eventBuffer.clear()
        evidenceBuffer.clear()
        observedSources.clear()
        inaccessibleSources.clear()
        seenLogLines.clear()
        seenDmesgLines.clear()
        lastSysfsValues.clear()
        capturedSnapshots.clear()
        eventCounter.set(0)
        bufferTruncated = false
        enrollmentOpenedMarked = false
        initialFingerprintDump = null
        latestFingerprintDump = null
        latestSurfaceFlingerSnippet = null
        pollTick = 0

        sessionStartNanos = System.nanoTime()
        val nowCivil = System.currentTimeMillis()

        // Pick targeted sysfs nodes discovered in Phase 1
        targetSysfsPaths = coldSession?.probeResults
            ?.filter { it.domain == ProbeDomain.DISPLAY || it.domain == ProbeDomain.TOUCH || it.domain == ProbeDomain.KERNEL }
            ?.flatMap { it.items }
            ?.mapNotNull { SafeSystemPath.parse(it.location) }
            ?.filter { path ->
                val p = path.value.lowercase()
                p.startsWith("/sys/") && (
                    p.contains("hbm") || p.contains("lhbm") || p.contains("brightness") ||
                        p.contains("fod") || p.contains("dim") || p.contains("finger") ||
                        p.contains("udfps")
                    )
            }
            ?.distinctBy { it.value }
            ?.take(12)
            ?: emptyList()

        recordSyntheticOrDirectEvent(
            type = TimelineEventType.SESSION_STARTED,
            source = "LiveTraceCoordinator",
            data = "Targeted sources=${targetSysfsPaths.size} sysfs nodes + logcat(main,system,events) + dmesg + dumpsys + procfs",
            confidence = ConfidenceLevel.HIGH,
            observationType = ObservationType.STATE_TRANSITION,
            accessLevel = AccessLevel.ANDROID_API,
            monotonicNanos = sessionStartNanos,
            civilMs = nowCivil
        )

        _progress.value = LiveTraceProgress(
            isRunning = true,
            elapsedMs = 0L,
            eventCount = eventBuffer.size,
            observedSources = observedSources.toList(),
            inaccessibleSources = inaccessibleSources.toList(),
            latestEventSummary = "Session started"
        )

        collectorJob = scope.launch {
            val priv = privilegeManager.refreshStatus()
            val allowRoot = priv.rootState == RootState.GRANTED_VERIFIED
            lastAllowRoot = allowRoot

            // Baseline procfs & dumpsys before/during enrollment
            captureProcessSnapshots(allowRoot)
            captureDumpsysSnapshots(allowRoot, isBaseline = true)
            if (allowRoot) {
                // Prime seenDmesgLines with historical kernel log lines so only runtime enrollment lines emit events
                primeDmesgBaseline()
            }

            while (isActive) {
                pollOnce(allowRoot)
                pollTick++
                if (pollTick % DUMPSYS_POLL_EVERY_N == 0) {
                    captureDumpsysSnapshots(allowRoot, isBaseline = false)
                }
                if (pollTick % PROCFS_POLL_EVERY_N == 0) {
                    captureProcessSnapshots(allowRoot)
                }

                val elapsed = ((System.nanoTime() - sessionStartNanos) / 1_000_000L).coerceAtLeast(0L)
                _progress.value = LiveTraceProgress(
                    isRunning = true,
                    elapsedMs = elapsed,
                    eventCount = eventBuffer.size,
                    observedSources = observedSources.toList(),
                    inaccessibleSources = inaccessibleSources.toList(),
                    latestEventSummary = eventBuffer.lastOrNull()?.let { "${it.type.name}: ${it.data.take(64)}" }
                )
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    fun markEnrollmentIntentOpened(intentAction: String) {
        if (!enrollmentOpenedMarked && _progress.value.isRunning) {
            enrollmentOpenedMarked = true
            recordSyntheticOrDirectEvent(
                type = TimelineEventType.ENROLLMENT_OPENED,
                source = "SystemEnrollmentIntent",
                data = "Launched $intentAction",
                confidence = ConfidenceLevel.HIGH,
                observationType = ObservationType.STATE_TRANSITION,
                accessLevel = AccessLevel.ANDROID_API,
                monotonicNanos = System.nanoTime(),
                civilMs = System.currentTimeMillis()
            )
        }
    }

    suspend fun finishAndCollect(): Pair<LiveTraceData, List<EvidenceRecord>> {
        stopInternal()
        // Final post-enrollment capture of procfs & dumpsys while HAL/SystemUI state is fresh
        captureProcessSnapshots(lastAllowRoot)
        captureDumpsysSnapshots(lastAllowRoot, isBaseline = false)

        val endNanos = System.nanoTime()
        val durationMs = ((endNanos - sessionStartNanos) / 1_000_000L).coerceAtLeast(0L)

        // Verify post-return biometric state without assuming Intent returned result
        val bioSnapshot = AndroidBiometricInspector(context).inspectBiometricState()
        val eventsCopy = linkNeighborEvents(eventBuffer.toList())
        val evidenceCopy = evidenceBuffer.toList()
        val fpDelta = computeFingerprintDelta(initialFingerprintDump, latestFingerprintDump)

        val liveData = LiveTraceData(
            sessionStartedMonotonicNanos = sessionStartNanos,
            sessionEndedMonotonicNanos = endNanos,
            durationMs = durationMs,
            enrollmentOpened = enrollmentOpenedMarked,
            enrollmentReturnedWithBiometricCheck = bioSnapshot.statusCodeLabel,
            observedSources = observedSources.toList(),
            inaccessibleSources = inaccessibleSources.toList(),
            events = eventsCopy,
            rawBufferTruncated = bufferTruncated,
            runtimeSnapshots = capturedSnapshots.values.toList(),
            surfaceFlingerSnapshot = latestSurfaceFlingerSnippet,
            dumpsysFingerprintDelta = fpDelta
        )
        return liveData to evidenceCopy
    }

    private suspend fun primeDmesgBaseline() {
        val dmesg = shellExecutor.execute(
            ShellCommandSpec.DmesgTail(lines = 250),
            useRoot = true,
            timeoutMs = 2_000L,
            maxOutputBytes = 65_536
        )
        if (dmesg.exitCode == 0 && dmesg.stdout.isNotBlank()) {
            observedSources += "dmesg"
            dmesg.stdout.lineSequence().forEach { line ->
                val trimmed = line.trim()
                if (trimmed.isNotEmpty() && LiveEventNormalizer.isFodRelevantLog(trimmed)) {
                    seenDmesgLines.add(trimmed)
                }
            }
        } else if (dmesg.denied) {
            inaccessibleSources += "dmesg (permission denied)"
        }
    }

    private suspend fun pollOnce(allowRoot: Boolean) {
        val nowMono = System.nanoTime()
        val nowCivil = System.currentTimeMillis()

        // 1. Poll targeted logcat lines across main, system, events
        val logRes = shellExecutor.execute(
            ShellCommandSpec.LogcatSnapshot(listOf("main", "system", "events"), lines = 180),
            useRoot = allowRoot,
            timeoutMs = 2_000L,
            maxOutputBytes = 98_304
        )
        if (logRes.exitCode == 0 && logRes.stdout.isNotBlank()) {
            observedSources += "logcat(main,system,events)"
            logRes.stdout.lineSequence().forEach { line ->
                val trimmed = line.trim()
                if (trimmed.isEmpty() || !LiveEventNormalizer.isFodRelevantLog(trimmed)) return@forEach
                if (seenLogLines.add(trimmed)) {
                    if (seenLogLines.size > MAX_SEEN_LINES) seenLogLines.clear()
                    val parsed = LiveEventNormalizer.classifyLogLine(
                        line = trimmed,
                        source = "logcat",
                        sessionStartNanos = sessionStartNanos,
                        monotonicNanos = nowMono,
                        civilMs = nowCivil,
                        eventCounter = eventCounter,
                        accessLevel = if (logRes.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                    )
                    if (parsed != null) {
                        appendBounded(parsed.first, parsed.second)
                    }
                }
            }
        } else if (logRes.denied) {
            inaccessibleSources += "logcat (permission denied)"
        }

        // 2. Poll Root dmesg for live kernel driver FOD / touch / DRM HBM messages
        if (allowRoot) {
            val dmesgRes = shellExecutor.execute(
                ShellCommandSpec.DmesgTail(lines = 250),
                useRoot = true,
                timeoutMs = 2_000L,
                maxOutputBytes = 65_536
            )
            if (dmesgRes.exitCode == 0 && dmesgRes.stdout.isNotBlank()) {
                observedSources += "dmesg"
                dmesgRes.stdout.lineSequence().forEach { line ->
                    val trimmed = line.trim()
                    if (trimmed.isEmpty() || !LiveEventNormalizer.isFodRelevantLog(trimmed)) return@forEach
                    if (seenDmesgLines.add(trimmed)) {
                        if (seenDmesgLines.size > MAX_SEEN_LINES) seenDmesgLines.clear()
                        val parsed = LiveEventNormalizer.classifyLogLine(
                            line = trimmed,
                            source = "dmesg",
                            sessionStartNanos = sessionStartNanos,
                            monotonicNanos = System.nanoTime(),
                            civilMs = System.currentTimeMillis(),
                            eventCounter = eventCounter,
                            accessLevel = AccessLevel.ROOT_SU
                        )
                        if (parsed != null) {
                            appendBounded(parsed.first, parsed.second)
                        }
                    }
                }
            } else if (dmesgRes.denied) {
                inaccessibleSources += "dmesg (permission denied)"
            }
        }

        // 3. Poll targeted sysfs display/touch/fod nodes discovered in Phase 1
        for (path in targetSysfsPaths) {
            val read = shellExecutor.execute(
                ShellCommandSpec.ReadSystemFile(path),
                useRoot = allowRoot,
                timeoutMs = 1_200L,
                maxOutputBytes = 1024
            )
            if (read.exitCode == 0) {
                observedSources += path.value
                val newVal = read.stdout.trim()
                val prevVal = lastSysfsValues.put(path.value, newVal)
                if (prevVal != null && prevVal != newVal) {
                    val lowerPath = path.value.lowercase()
                    val evtType = when {
                        (lowerPath.contains("hbm") || lowerPath.contains("lhbm")) &&
                            (newVal == "1" || newVal.equals("true", true)) ->
                            TimelineEventType.HBM_ENABLED
                        (lowerPath.contains("hbm") || lowerPath.contains("lhbm")) &&
                            (newVal == "0" || newVal.equals("false", true)) ->
                            TimelineEventType.HBM_DISABLED
                        lowerPath.contains("fod") || lowerPath.contains("touch") ->
                            TimelineEventType.TOUCH_EVENT_OBSERVED
                        else -> TimelineEventType.HBM_ENABLED
                    }
                    recordSyntheticOrDirectEvent(
                        type = evtType,
                        source = path.value,
                        data = "${path.value}: $prevVal -> $newVal",
                        confidence = ConfidenceLevel.HIGH,
                        observationType = ObservationType.STATE_TRANSITION,
                        accessLevel = if (read.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL,
                        monotonicNanos = System.nanoTime(),
                        civilMs = System.currentTimeMillis()
                    )
                }
            } else if (read.denied) {
                inaccessibleSources += "${path.value} (denied)"
            }
        }
    }

    private suspend fun captureProcessSnapshots(allowRoot: Boolean) {
        val psRes = shellExecutor.execute(
            ShellCommandSpec.ListProcesses(),
            useRoot = allowRoot,
            timeoutMs = 2_000L,
            maxOutputBytes = 65_536
        )
        if (psRes.exitCode != 0 || psRes.stdout.isBlank()) {
            if (psRes.denied) inaccessibleSources += "ps -A (denied)"
            return
        }
        observedSources += "ps -A"

        val matchingProcs = psRes.stdout.lineSequence()
            .mapNotNull { line ->
                val parts = line.trim().split(Regex("\\s+"))
                if (parts.size < 2) return@mapNotNull null
                val pid = parts[0].toIntOrNull() ?: return@mapNotNull null
                val name = parts.last()
                val lower = name.lowercase()
                val isTarget = lower.contains("systemui") ||
                    lower.contains("surfaceflinger") ||
                    lower.contains("fingerprint") ||
                    lower.contains("biometric") ||
                    lower.contains("hwcomposer") ||
                    lower.contains("goodix") ||
                    lower.contains("silead") ||
                    lower.contains("fpc")
                if (isTarget) pid to name else null
            }
            .distinctBy { it.first }
            .take(6)
            .toList()

        for ((pid, procName) in matchingProcs) {
            val fdRes = shellExecutor.execute(
                ShellCommandSpec.InspectProcPid(pid, AllowedProcTarget.FD),
                useRoot = allowRoot,
                timeoutMs = 1_500L,
                maxOutputBytes = 32_768
            )
            val mapsRes = shellExecutor.execute(
                ShellCommandSpec.InspectProcPid(pid, AllowedProcTarget.MAPS),
                useRoot = allowRoot,
                timeoutMs = 1_800L,
                maxOutputBytes = 131_072
            )

            val fds = if (fdRes.exitCode == 0) {
                observedSources += "/proc/$pid/fd"
                fdRes.stdout.lineSequence()
                    .map { it.trim() }
                    .filter { line ->
                        val l = line.lowercase()
                        l.contains("/dev/") || l.contains("/sys/") || l.contains("drm") ||
                            l.contains("input") || l.contains("goodix") || l.contains("fpc") ||
                            l.contains("silead") || l.contains("focal") || l.contains("egis") ||
                            l.contains("finger") || l.contains("hbm") || l.contains("fod")
                    }
                    .distinct()
                    .take(25)
                    .toList()
            } else {
                if (fdRes.denied) inaccessibleSources += "/proc/$pid/fd ($procName denied)"
                emptyList()
            }

            val libs = if (mapsRes.exitCode == 0) {
                observedSources += "/proc/$pid/maps"
                mapsRes.stdout.lineSequence()
                    .mapNotNull { line ->
                        val path = line.trim().split(Regex("\\s+")).lastOrNull()?.trim() ?: return@mapNotNull null
                        if (!path.startsWith("/")) return@mapNotNull null
                        val l = path.lowercase()
                        val relevant = (path.endsWith(".so") || path.endsWith(".apk") || path.endsWith(".jar")) &&
                            (l.contains("finger") || l.contains("biometric") || l.contains("goodix") ||
                                l.contains("fpc") || l.contains("silead") || l.contains("focal") ||
                                l.contains("egis") || l.contains("udfps") || l.contains("fod") ||
                                l.contains("hbm") || l.contains("display") || l.contains("composer") ||
                                l.contains("systemui"))
                        if (relevant) path else null
                    }
                    .distinct()
                    .take(30)
                    .toList()
            } else {
                if (mapsRes.denied) inaccessibleSources += "/proc/$pid/maps ($procName denied)"
                emptyList()
            }

            if (fds.isNotEmpty() || libs.isNotEmpty()) {
                val existing = capturedSnapshots[pid]
                val mergedFds = ((existing?.openFodDescriptors.orEmpty()) + fds).distinct().take(30)
                val mergedLibs = ((existing?.loadedFodLibraries.orEmpty()) + libs).distinct().take(35)
                capturedSnapshots[pid] = ProcessRuntimeSnapshot(
                    processName = procName,
                    pid = pid,
                    openFodDescriptors = mergedFds,
                    loadedFodLibraries = mergedLibs,
                    epistemicLevel = EpistemicLevel.PROVED
                )
            }
        }
    }

    private suspend fun captureDumpsysSnapshots(allowRoot: Boolean, isBaseline: Boolean) {
        val sfRes = shellExecutor.execute(
            ShellCommandSpec.Dumpsys(AllowedDumpsysService.SURFACE_FLINGER),
            useRoot = allowRoot,
            timeoutMs = 2_000L,
            maxOutputBytes = 98_304
        )
        if (sfRes.exitCode == 0 && sfRes.stdout.isNotBlank()) {
            observedSources += "dumpsys SurfaceFlinger"
            val fodLayers = sfRes.stdout.lineSequence()
                .map { it.trim() }
                .filter { line ->
                    val l = line.lowercase()
                    l.contains("udfps") || l.contains("biometric") || l.contains("fod") ||
                        l.contains("hbm") || l.contains("lhbm") || l.contains("dim") ||
                        l.contains("fingerprint")
                }
                .distinct()
                .take(14)
                .toList()
            if (fodLayers.isNotEmpty()) {
                val joined = fodLayers.joinToString("\n")
                if (!isBaseline && latestSurfaceFlingerSnippet != joined) {
                    recordSyntheticOrDirectEvent(
                        type = TimelineEventType.UDFPS_UI_DISPLAYED,
                        source = "dumpsys SurfaceFlinger",
                        data = fodLayers.first().take(200),
                        confidence = ConfidenceLevel.HIGH,
                        observationType = ObservationType.DIRECT_OBSERVATION,
                        accessLevel = if (sfRes.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL,
                        monotonicNanos = System.nanoTime(),
                        civilMs = System.currentTimeMillis()
                    )
                }
                latestSurfaceFlingerSnippet = joined
            }
        } else if (sfRes.denied) {
            inaccessibleSources += "dumpsys SurfaceFlinger (denied)"
        }

        val fpRes = shellExecutor.execute(
            ShellCommandSpec.Dumpsys(AllowedDumpsysService.FINGERPRINT),
            useRoot = allowRoot,
            timeoutMs = 2_000L,
            maxOutputBytes = 65_536
        )
        if (fpRes.exitCode == 0 && fpRes.stdout.isNotBlank()) {
            observedSources += "dumpsys fingerprint"
            val summaryLines = fpRes.stdout.lineSequence()
                .map { it.trim() }
                .filter { line ->
                    val l = line.lowercase()
                    l.contains("sensor") || l.contains("udfps") || l.contains("client") ||
                        l.contains("enroll") || l.contains("hal") || l.contains("state") ||
                        l.contains("strength")
                }
                .take(18)
                .joinToString("\n")
            if (summaryLines.isNotBlank()) {
                if (isBaseline && initialFingerprintDump == null) {
                    initialFingerprintDump = summaryLines
                } else if (!isBaseline && latestFingerprintDump != summaryLines) {
                    recordSyntheticOrDirectEvent(
                        type = TimelineEventType.BIOMETRIC_SERVICE_READY,
                        source = "dumpsys fingerprint",
                        data = summaryLines.lineSequence().firstOrNull()?.take(200) ?: "FingerprintService state updated",
                        confidence = ConfidenceLevel.HIGH,
                        observationType = ObservationType.STATE_TRANSITION,
                        accessLevel = if (fpRes.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL,
                        monotonicNanos = System.nanoTime(),
                        civilMs = System.currentTimeMillis()
                    )
                }
                latestFingerprintDump = summaryLines
            }
        } else if (fpRes.denied) {
            inaccessibleSources += "dumpsys fingerprint (denied)"
        }
    }

    private fun computeFingerprintDelta(initial: String?, latest: String?): String? {
        if (latest == null) return initial
        if (initial == null || initial == latest) return latest.take(400)
        val initLines = initial.lines().toSet()
        val added = latest.lines().filter { it !in initLines }
        return if (added.isNotEmpty()) {
            "Delta:\n" + added.joinToString("\n").take(400)
        } else {
            latest.take(400)
        }
    }

    private fun recordSyntheticOrDirectEvent(
        type: TimelineEventType,
        source: String,
        data: String,
        confidence: ConfidenceLevel,
        observationType: ObservationType,
        accessLevel: AccessLevel,
        monotonicNanos: Long,
        civilMs: Long
    ) {
        val seq = eventCounter.incrementAndGet()
        val evId = "EV-LIVE-${seq.toString().padStart(4, '0')}"
        val evtId = "EVT-LIVE-${seq.toString().padStart(4, '0')}"
        val relMs = ((monotonicNanos - sessionStartNanos) / 1_000_000L).coerceAtLeast(0L)
        observedSources += source

        val evidence = EvidenceRecord(
            id = evId,
            source = source,
            resourceType = "LIVE_TELEMETRY:${type.name}",
            observedValue = data,
            civilTimestampMs = civilMs,
            monotonicNanos = monotonicNanos,
            collectionMethod = "LiveTracer:$source",
            accessLevel = accessLevel,
            executionResult = "OBSERVED",
            discoveryStatus = DiscoveryStatus.FOUND,
            epistemicLevel = EpistemicLevel.PROVED
        )
        val event = TimelineEvent(
            id = evtId,
            type = type,
            monotonicNanos = monotonicNanos,
            relativeMs = relMs,
            civilTimestampMs = civilMs,
            source = source,
            data = data,
            evidenceId = evId,
            confidence = confidence,
            observationType = observationType
        )
        appendBounded(event, evidence)
    }

    @Synchronized
    private fun appendBounded(event: TimelineEvent, evidence: EvidenceRecord) {
        if (eventBuffer.size >= MAX_TIMELINE_EVENTS) {
            eventBuffer.removeFirst()
            bufferTruncated = true
        }
        if (evidenceBuffer.size >= MAX_TIMELINE_EVENTS) {
            evidenceBuffer.removeFirst()
        }
        eventBuffer.addLast(event)
        evidenceBuffer.addLast(evidence)
    }

    private fun linkNeighborEvents(events: List<TimelineEvent>): List<TimelineEvent> {
        return events.mapIndexed { idx, evt ->
            val neighbors = buildList {
                if (idx > 0) add(events[idx - 1].id)
                if (idx + 1 < events.size) add(events[idx + 1].id)
            }
            evt.copy(relatedEventIds = neighbors)
        }
    }

    private fun stopInternal() {
        collectorJob?.cancel()
        collectorJob = null
        _progress.value = _progress.value.copy(isRunning = false)
    }

    companion object {
        private const val MAX_TIMELINE_EVENTS = 600
        private const val MAX_SEEN_LINES = 1500
        private const val POLL_INTERVAL_MS = 450L
        private const val DUMPSYS_POLL_EVERY_N = 4
        private const val PROCFS_POLL_EVERY_N = 8
    }
}
