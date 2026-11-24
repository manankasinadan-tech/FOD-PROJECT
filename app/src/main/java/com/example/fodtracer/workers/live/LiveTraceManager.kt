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
            lower.contains("hbm") && (lower.contains("enable") || lower.contains("on") || lower.contains("enter") || lower.contains("= 1") || lower.contains("=1")) ->
                TimelineEventType.HBM_ENABLED to ConfidenceLevel.HIGH
            lower.contains("hbm") && (lower.contains("disable") || lower.contains("off") || lower.contains("exit") || lower.contains("= 0") || lower.contains("=0")) ->
                TimelineEventType.HBM_DISABLED to ConfidenceLevel.HIGH
            lower.contains("udfps") && (lower.contains("show") || lower.contains("overlay") || lower.contains("onacquired") || lower.contains("display")) ->
                TimelineEventType.UDFPS_UI_DISPLAYED to ConfidenceLevel.HIGH
            lower.contains("onpointerdown") || lower.contains("fingerdown") || lower.contains("touch_down") || lower.contains("fod_touch") ->
                TimelineEventType.TOUCH_EVENT_OBSERVED to ConfidenceLevel.HIGH
            lower.contains("capture") || lower.contains("acquire") || lower.contains("image") && (lower.contains("fp") || lower.contains("goodix") || lower.contains("biometric")) ->
                TimelineEventType.IMAGE_ACQUISITION to ConfidenceLevel.MEDIUM
            lower.contains("enroll") && (lower.contains("remaining") || lower.contains("progress") || lower.contains("step")) ->
                TimelineEventType.ENROLLMENT_PROGRESS to ConfidenceLevel.HIGH
            lower.contains("enroll") && (lower.contains("complete") || lower.contains("success") || lower.contains("finished")) ->
                TimelineEventType.SESSION_COMPLETED to ConfidenceLevel.HIGH
            lower.contains("biometric") && (lower.contains("ready") || lower.contains("enroll(") || lower.contains("startenroll")) ->
                TimelineEventType.BIOMETRIC_SERVICE_READY to ConfidenceLevel.MEDIUM
            lower.contains("process") && (lower.contains("finger") || lower.contains("template") || lower.contains("goodix") || lower.contains("fpc")) ->
                TimelineEventType.BIOMETRIC_PROCESSING to ConfidenceLevel.MEDIUM
            lower.contains("error") || lower.contains("timeout") || lower.contains("failed") || lower.contains("avc: denied") ->
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
    private val lastSysfsValues = HashMap<String, String>()
    private val eventCounter = AtomicInteger(0)

    private var sessionStartNanos: Long = 0L
    private var bufferTruncated = false
    private var targetSysfsPaths: List<SafeSystemPath> = emptyList()
    private var enrollmentOpenedMarked = false

    fun startSession(coldSession: DiagnosticSession?) {
        stopInternal()
        eventBuffer.clear()
        evidenceBuffer.clear()
        observedSources.clear()
        inaccessibleSources.clear()
        seenLogLines.clear()
        lastSysfsValues.clear()
        eventCounter.set(0)
        bufferTruncated = false
        enrollmentOpenedMarked = false

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
                    p.contains("hbm") || p.contains("brightness") ||
                        p.contains("fod") || p.contains("dim") || p.contains("finger")
                    )
            }
            ?.distinctBy { it.value }
            ?.take(8)
            ?: emptyList()

        recordSyntheticOrDirectEvent(
            type = TimelineEventType.SESSION_STARTED,
            source = "LiveTraceCoordinator",
            data = "Targeted sources=${targetSysfsPaths.size} sysfs nodes + logcat + dumpsys",
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

            while (isActive) {
                pollOnce(allowRoot)
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
        val endNanos = System.nanoTime()
        val durationMs = ((endNanos - sessionStartNanos) / 1_000_000L).coerceAtLeast(0L)

        // Verify post-return biometric state without assuming Intent returned result
        val bioSnapshot = AndroidBiometricInspector(context).inspectBiometricState()
        val eventsCopy = linkNeighborEvents(eventBuffer.toList())
        val evidenceCopy = evidenceBuffer.toList()

        val liveData = LiveTraceData(
            sessionStartedMonotonicNanos = sessionStartNanos,
            sessionEndedMonotonicNanos = endNanos,
            durationMs = durationMs,
            enrollmentOpened = enrollmentOpenedMarked,
            enrollmentReturnedWithBiometricCheck = bioSnapshot.statusCodeLabel,
            observedSources = observedSources.toList(),
            inaccessibleSources = inaccessibleSources.toList(),
            events = eventsCopy,
            rawBufferTruncated = bufferTruncated
        )
        return liveData to evidenceCopy
    }

    private suspend fun pollOnce(allowRoot: Boolean) {
        val nowMono = System.nanoTime()
        val nowCivil = System.currentTimeMillis()

        // 1. Poll targeted logcat lines
        val logRes = shellExecutor.execute(
            ShellCommandSpec.LogcatSnapshot(listOf("main", "system"), lines = 120),
            useRoot = allowRoot,
            timeoutMs = 2_000L,
            maxOutputBytes = 65_536
        )
        if (logRes.exitCode == 0 && logRes.stdout.isNotBlank()) {
            observedSources += "logcat(main,system)"
            logRes.stdout.lineSequence().forEach { line ->
                val trimmed = line.trim()
                if (trimmed.isEmpty() || !isFodRelevantLog(trimmed)) return@forEach
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

        // 2. Poll targeted sysfs display/touch/fod nodes discovered in Phase 1
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
                        lowerPath.contains("hbm") && (newVal == "1" || newVal.equals("true", true)) ->
                            TimelineEventType.HBM_ENABLED
                        lowerPath.contains("hbm") && (newVal == "0" || newVal.equals("false", true)) ->
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

    private fun isFodRelevantLog(line: String): Boolean {
        val l = line.lowercase()
        return l.contains("udfps") || l.contains("fingerprint") || l.contains("biometric") ||
            l.contains("fod") || l.contains("hbm") || l.contains("lhbm") ||
            l.contains("goodix") || l.contains("fpc") || l.contains("authcontroller")
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
        private const val MAX_TIMELINE_EVENTS = 500
        private const val MAX_SEEN_LINES = 1000
        private const val POLL_INTERVAL_MS = 900L
    }
}
