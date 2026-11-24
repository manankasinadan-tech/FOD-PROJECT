package com.example

import com.example.fodtracer.core.anomaly.AnomalyEngine
import com.example.fodtracer.core.comparator.ComparatorEngine
import com.example.fodtracer.core.comparator.ReferenceBaselineFixtures
import com.example.fodtracer.core.correlation.CorrelationEngine
import com.example.fodtracer.core.evidence.EvidenceEngine
import com.example.fodtracer.core.solution.SolutionEngine
import com.example.fodtracer.data.serialization.FodJson
import com.example.fodtracer.data.serialization.ReportAnonymizer
import com.example.fodtracer.domain.interfaces.SafeSystemPath
import com.example.fodtracer.domain.interfaces.ShellCommandSpec
import com.example.fodtracer.domain.models.*
import com.example.fodtracer.system.shell.SafeShellExecutor
import com.example.fodtracer.workers.live.LiveEventNormalizer
import kotlinx.coroutines.test.runTest
import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.atomic.AtomicInteger

class FodEnginesAndSecurityTest {

    @Test
    fun `SafeSystemPath rejects traversal, arbitrary dirs, and shell metacharacters`() {
        assertNull(SafeSystemPath.parse("/sys/../etc/passwd"))
        assertNull(SafeSystemPath.parse("/data/local/tmp/exploit"))
        assertNull(SafeSystemPath.parse("/sys/class/backlight;rm -rf /"))
        assertNull(SafeSystemPath.parse("/sdcard/FODtracer"))
        assertNull(SafeSystemPath.parse(""))

        assertNotNull(SafeSystemPath.parse("/sys/class/drm/card0-DSI-1/hbm"))
        assertNotNull(SafeSystemPath.parse("/vendor/etc/permissions/android.hardware.fingerprint.xml"))
        assertNotNull(SafeSystemPath.parse("/proc/cpuinfo"))
    }

    @Test
    fun `SafeShellExecutor denies root command cleanly when su binary is absent`() = runTest {
        val executor = SafeShellExecutor(suBinaryResolver = { null })
        val result = executor.execute(ShellCommandSpec.IdCommand, useRoot = true)
        assertTrue(result.denied)
        assertEquals(-1, result.exitCode)
        assertTrue(result.stderr.contains("su", ignoreCase = true))
    }

    @Test
    fun `Evidence, Correlation, and Anomaly engines never promote INACCESSIBLE to NOT_FOUND or fake anomaly`() {
        val rom = ReferenceBaselineFixtures.createFailingGsiBaseline()
        val blockedProbe = ProbeResult(
            probeId = "probe_kernel",
            domain = ProbeDomain.KERNEL,
            status = DiscoveryStatus.INACCESSIBLE,
            accessLevelUsed = AccessLevel.UNPRIVILEGED_SHELL,
            summary = "Blocked by SELinux",
            items = listOf(
                ProbeFindingItem(
                    key = "kernel.sysfs_fod",
                    value = "Permission denied",
                    location = "/sys/devices/platform/soc/fod",
                    discoveryStatus = DiscoveryStatus.INACCESSIBLE,
                    epistemicLevel = EpistemicLevel.INACCESSIBLE,
                    accessLevel = AccessLevel.UNPRIVILEGED_SHELL
                )
            ),
            durationMs = 10,
            civilTimestampMs = 1_760_000_000_000L,
            inaccessibleReasons = listOf("SELinux avc denied on /sys/devices/platform/soc/fod")
        )

        val evidenceEngine = EvidenceEngine()
        val evidence = evidenceEngine.buildColdEvidence(listOf(blockedProbe))
        assertEquals(1, evidence.size)
        assertEquals(EpistemicLevel.INACCESSIBLE, evidence.first().epistemicLevel)
        assertEquals(DiscoveryStatus.INACCESSIBLE, evidence.first().discoveryStatus)

        val anomalyOutput = AnomalyEngine().analyze(
            environment = rom.environment,
            probeResults = listOf(blockedProbe),
            components = rom.components.map {
                if (it.role == ComponentRole.KERNEL_DRIVER) {
                    it.copy(discoveryStatus = DiscoveryStatus.INACCESSIBLE, epistemicLevel = EpistemicLevel.INACCESSIBLE)
                } else it
            },
            evidence = evidence,
            liveTrace = null
        )

        // Must emit access limitation hypothesis, NOT fabricate a CRITICAL hardware anomaly
        assertTrue(anomalyOutput.hypotheses.any { it.id == "HYP-ACCESS-LIMITS" })
        assertFalse(anomalyOutput.anomalies.any { it.id == "ANOM-NO-HBM-ON-TOUCH" })
    }

    @Test
    fun `AnomalyEngine detects ANOM-NO-HBM-ON-TOUCH only when monitored and touch observed without HBM`() {
        val gsi = ReferenceBaselineFixtures.createFailingGsiBaseline()
        val out = AnomalyEngine().analyze(
            environment = gsi.environment,
            probeResults = gsi.probeResults,
            components = gsi.components,
            evidence = gsi.evidence,
            liveTrace = gsi.liveTrace
        )
        assertTrue(out.anomalies.any { it.id == "ANOM-NO-HBM-ON-TOUCH" })

        val unmonitoredLive = gsi.liveTrace!!.copy(
            observedSources = listOf("SystemEnrollmentIntent"),
            inaccessibleSources = listOf("logcat (permission denied)", "/sys/class/drm/hbm (denied)")
        )
        val outUnmonitored = AnomalyEngine().analyze(
            environment = gsi.environment,
            probeResults = gsi.probeResults,
            components = gsi.components,
            evidence = gsi.evidence,
            liveTrace = unmonitoredLive
        )
        assertFalse(outUnmonitored.anomalies.any { it.id == "ANOM-NO-HBM-ON-TOUCH" })
        assertTrue(outUnmonitored.hypotheses.any { it.id == "HYP-HBM-UNMONITORED" })
    }

    @Test
    fun `LiveEventNormalizer classifies FOD telemetry lines with monotonic deltas`() {
        val counter = AtomicInteger(0)
        val t0 = 1_000_000_000L
        val res1 = LiveEventNormalizer.classifyLogLine(
            line = "UdfpsController: showUdfpsOverlay sensorId=0",
            source = "logcat",
            sessionStartNanos = t0,
            monotonicNanos = t0 + 120_000_000L,
            civilMs = 1_760_000_000_120L,
            eventCounter = counter,
            accessLevel = AccessLevel.ROOT_SU
        )
        assertNotNull(res1)
        assertEquals(TimelineEventType.UDFPS_UI_DISPLAYED, res1!!.first.type)
        assertEquals(120L, res1.first.relativeMs)
        assertEquals(EpistemicLevel.PROVED, res1.second.epistemicLevel)

        val res2 = LiveEventNormalizer.classifyLogLine(
            line = "DisplayHBM: hbm enable = 1",
            source = "logcat",
            sessionStartNanos = t0,
            monotonicNanos = t0 + 250_000_000L,
            civilMs = 1_760_000_000_250L,
            eventCounter = counter,
            accessLevel = AccessLevel.ROOT_SU
        )
        assertNotNull(res2)
        assertEquals(TimelineEventType.HBM_ENABLED, res2!!.first.type)
        assertEquals(250L, res2.first.relativeMs)
    }

    @Test
    fun `ComparatorEngine distinguishes critical GSI divergences from benign build properties`() {
        val rom = ReferenceBaselineFixtures.createWorkingCustomRomBaseline()
        val gsi = ReferenceBaselineFixtures.createFailingGsiBaseline()
        val report = ComparatorEngine().compare(rom, gsi)

        assertTrue(report.compatibility.isComparable)
        assertEquals(100, report.compatibility.hardwareMatchScore)
        assertTrue(report.structuralDiffs.any { it.impact == DiffImpact.CRITICAL && it.classification == DiffClassification.MISSING })
        assertTrue(report.behavioralDiffs.any { it.eventType == TimelineEventType.HBM_ENABLED && it.classification == DiffClassification.MISSING })
        assertTrue(report.anomaliesOnlyInGsiB.any { it.id == "ANOM-NO-HBM-ON-TOUCH" })
    }

    @Test
    fun `SolutionEngine classifies GSI_ONLY_CONFIGURATION, GSI_ONLY_RUNTIME, and OUTSIDE_GSI_SCOPE`() {
        val rom = ReferenceBaselineFixtures.createWorkingCustomRomBaseline()
        val gsi = ReferenceBaselineFixtures.createFailingGsiBaseline()
        val report = ComparatorEngine().compare(rom, gsi)
        val proposals = SolutionEngine().evaluateComparison(report, rom, gsi)

        assertTrue(proposals.any { it.category == SolutionCategory.GSI_ONLY_CONFIGURATION })
        assertTrue(proposals.any { it.category == SolutionCategory.GSI_ONLY_RUNTIME })

        val vendorAvcSession = gsi.copy(
            anomalies = listOf(
                AnomalyRecord(
                    id = "ANOM-SELINUX-AVC",
                    title = "AVC denied on vendor sysfs",
                    description = "avc: denied on vendor_hal_fingerprint",
                    componentId = null,
                    componentName = "SELinux",
                    severity = AnomalySeverity.HIGH,
                    epistemicLevel = EpistemicLevel.PROVED,
                    justifyingSources = listOf("dmesg"),
                    evidenceIds = listOf("EV-AVC-1")
                )
            ),
            evidence = listOf(
                EvidenceRecord(
                    id = "EV-AVC-1",
                    source = "dmesg",
                    resourceType = "SELINUX:selinux.avc_denial",
                    observedValue = "avc: denied { write } for comm=\"hal_fingerprint\" tcontext=u:object_r:vendor_sysfs_fod:s0",
                    civilTimestampMs = 1L,
                    monotonicNanos = 1L,
                    collectionMethod = "probe_selinux",
                    accessLevel = AccessLevel.ROOT_SU,
                    executionResult = "FOUND",
                    discoveryStatus = DiscoveryStatus.FOUND,
                    epistemicLevel = EpistemicLevel.PROVED
                )
            )
        )
        val avcSolutions = SolutionEngine().evaluateDiagnostic(vendorAvcSession)
        assertTrue(avcSolutions.any {
            it.category == SolutionCategory.OUTSIDE_GSI_SCOPE && it.feasibility == FeasibilityLevel.NOT_SUPPORTED_BY_GSI
        })
    }

    @Test
    fun `ReportAnonymizer redacts sensitive identifiers non-destructively`() {
        val original = ReferenceBaselineFixtures.createWorkingCustomRomBaseline()
        val withSecrets = original.copy(
            evidence = original.evidence + EvidenceRecord(
                id = "EV-SENS",
                source = "getprop",
                resourceType = "PROPERTIES:ro.boot.serialno",
                observedValue = "123456789012345 aa:bb:cc:dd:ee:ff",
                civilTimestampMs = 1L,
                monotonicNanos = 1L,
                collectionMethod = "probe_properties",
                accessLevel = AccessLevel.UNPRIVILEGED_SHELL,
                executionResult = "FOUND",
                discoveryStatus = DiscoveryStatus.FOUND,
                epistemicLevel = EpistemicLevel.PROVED
            )
        )
        val anonymized = ReportAnonymizer.anonymize(withSecrets)
        assertTrue(anonymized.isAnonymized)
        assertNotEquals(withSecrets.sessionId, anonymized.sessionId)
        val redactedEv = anonymized.evidence.first { it.id == "EV-SENS" }
        assertEquals("[REDACTED]", redactedEv.observedValue)
        // Original must remain untouched
        assertFalse(withSecrets.isAnonymized)
        assertEquals("123456789012345 aa:bb:cc:dd:ee:ff", withSecrets.evidence.first { it.id == "EV-SENS" }.observedValue)
    }
}
