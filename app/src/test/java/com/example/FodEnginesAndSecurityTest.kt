package com.example

import com.example.fodtracer.core.anomaly.AnomalyEngine
import com.example.fodtracer.core.comparator.ComparatorEngine
import com.example.fodtracer.core.comparator.ReferenceBaselineFixtures
import com.example.fodtracer.core.correlation.CorrelationEngine
import com.example.fodtracer.core.disasm.DexAndApkDisassembler
import com.example.fodtracer.core.disasm.ElfDisassembler
import com.example.fodtracer.core.disasm.FodLogicReconstructor
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
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
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
        assertNotNull(SafeSystemPath.parse("/apex/com.android.runtime/lib64/bionic/libc.so"))
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

    @Test
    fun `ElfDisassembler extracts DT_NEEDED, symbols, rodata strings, and AArch64 ADRP-ADD resolution`() {
        val elfBytes = buildSyntheticAarch64Elf()
        val parsed = ElfDisassembler.analyze(
            id = "DIS-ELF-001",
            path = "/vendor/lib64/hw/fingerprint.fod.so",
            partition = PartitionOrigin.VENDOR,
            bytes = elfBytes
        )
        assertNotNull(parsed)
        val (artifact, fullReport) = parsed!!
        assertEquals("AArch64 (ARM64)", artifact.architecture)
        assertTrue(artifact.neededLibraries.contains("libgoodix_fod.so"))
        assertTrue(artifact.keySymbols.any { it.contains("enable_hbm_fod") })
        assertTrue(artifact.extractedStrings.contains("/sys/class/drm/card0-DSI-1/hbm"))
        assertTrue(fullReport.contains("adrp x0, 0x2000"))
        assertTrue(fullReport.contains("; \"/sys/class/drm/card0-DSI-1/hbm\""))
        assertTrue(fullReport.contains("ret"))
    }

    @Test
    fun `DexAndApkDisassembler parses FOD class names and Dalvik opcodes cleanly`() {
        val dexBytes = buildSyntheticFodDex()
        val out = DexAndApkDisassembler.parseDexBytes("classes.dex", dexBytes)
        assertNotNull(out)
        assertTrue(out!!.classSummaries.any { it.contains("UdfpsController") })
        assertTrue(out.disassemblyReport.contains("onFingerDown"))
        assertTrue(out.disassemblyReport.contains("const-string"))
        assertTrue(out.disassemblyReport.contains("return-void"))
    }

    @Test
    fun `FodLogicReconstructor keeps INACCESSIBLE stages unpromoted when root and live trace are absent`() {
        val blockedHal = ProbeResult(
            probeId = "probe_hal",
            domain = ProbeDomain.HAL,
            status = DiscoveryStatus.INACCESSIBLE,
            accessLevelUsed = AccessLevel.UNPRIVILEGED_SHELL,
            summary = "Denied",
            items = emptyList(),
            durationMs = 5,
            civilTimestampMs = 1L
        )
        val steps = FodLogicReconstructor.reconstruct(
            probeResults = listOf(blockedHal),
            artifacts = emptyList(),
            liveTrace = null
        )
        assertEquals(6, steps.size)
        val halStage = steps.first { it.order == 5 }
        assertEquals(EpistemicLevel.INACCESSIBLE, halStage.epistemicLevel)
        assertFalse(halStage.verifiedInLiveTrace)
    }

    private fun buildSyntheticAarch64Elf(): ByteArray {
        val dynStr = "\u0000libgoodix_fod.so\u0000enable_hbm_fod\u0000"
        val libNameOff = 1
        val symNameOff = 1 + "libgoodix_fod.so\u0000".length

        val shStrTab = "\u0000.shstrtab\u0000.dynstr\u0000.dynamic\u0000.dynsym\u0000.rodata\u0000.text\u0000"
        val rodataBytes = "/sys/class/drm/card0-DSI-1/hbm\u0000".toByteArray(StandardCharsets.US_ASCII)

        // .text at vaddr 0x1000, .rodata at vaddr 0x2000:
        // pc=0x1000: adrp x0, 0x2000 -> page delta = +0x1000 = (1 << 12) => immlo=1, immhi=0 => 0xB0000000
        // pc=0x1004: add x0, x0, #0  => 0x91000000
        // pc=0x1008: ret             => 0xD65F03C0
        val textBuf = ByteBuffer.allocate(16).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(0xB0000000.toInt()) // adrp x0, 0x2000
            putInt(0x91000000.toInt()) // add x0, x0, #0x0
            putInt(0xD65F03C0.toInt()) // ret
            putInt(0xD503201F.toInt()) // nop
        }.array()

        // .dynamic: DT_NEEDED(1) -> libNameOff, DT_NULL(0)
        val dynBuf = ByteBuffer.allocate(32).order(ByteOrder.LITTLE_ENDIAN).apply {
            putLong(1L); putLong(libNameOff.toLong())
            putLong(0L); putLong(0L)
        }.array()

        // .dynsym: 2 entries * 24 bytes (null + enable_hbm_fod)
        val symBuf = ByteBuffer.allocate(48).order(ByteOrder.LITTLE_ENDIAN).apply {
            // entry 0 null (24 bytes zero)
            position(24)
            putInt(symNameOff) // st_name
            put(0x12.toByte()) // st_info (GLOBAL FUNC)
            put(0.toByte())
            putShort(6.toShort()) // st_shndx (.text section index)
            putLong(0x1000L) // st_value
            putLong(16L) // st_size
        }.array()

        val shStrOff = 64
        val dynStrOff = shStrOff + shStrTab.length
        val dynOff = dynStrOff + dynStr.length
        val symOff = dynOff + dynBuf.size
        val rodataOff = symOff + symBuf.size
        val textOff = rodataOff + rodataBytes.size
        val shOff = textOff + textBuf.size

        val totalSize = shOff + 7 * 64
        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)

        // ELF64 header
        buf.put(0, 0x7F.toByte()); buf.put(1, 'E'.code.toByte()); buf.put(2, 'L'.code.toByte()); buf.put(3, 'F'.code.toByte())
        buf.put(4, 2.toByte()) // ELFCLASS64
        buf.put(5, 1.toByte()) // little endian
        buf.put(6, 1.toByte()) // EV_CURRENT
        buf.putShort(16, 3.toShort()) // ET_DYN
        buf.putShort(18, 183.toShort()) // EM_AARCH64
        buf.putLong(40, shOff.toLong())
        buf.putShort(58, 64.toShort()) // e_shentsize
        buf.putShort(60, 7.toShort())  // e_shnum
        buf.putShort(62, 1.toShort())  // e_shstrndx

        fun writeBytes(off: Int, data: ByteArray) {
            buf.position(off)
            buf.put(data)
        }
        writeBytes(shStrOff, shStrTab.toByteArray(StandardCharsets.US_ASCII))
        writeBytes(dynStrOff, dynStr.toByteArray(StandardCharsets.US_ASCII))
        writeBytes(dynOff, dynBuf)
        writeBytes(symOff, symBuf)
        writeBytes(rodataOff, rodataBytes)
        writeBytes(textOff, textBuf)

        fun writeShdr(index: Int, name: String, type: Int, addr: Long, offset: Long, size: Long, entSize: Long) {
            val base = shOff + index * 64
            val nameIdx = if (name.isEmpty()) 0 else shStrTab.indexOf(name)
            buf.putInt(base, nameIdx)
            buf.putInt(base + 4, type)
            buf.putLong(base + 16, addr)
            buf.putLong(base + 24, offset)
            buf.putLong(base + 32, size)
            buf.putLong(base + 56, entSize)
        }

        writeShdr(0, "", 0, 0L, 0L, 0L, 0L)
        writeShdr(1, ".shstrtab", 3, 0L, shStrOff.toLong(), shStrTab.length.toLong(), 0L)
        writeShdr(2, ".dynstr", 3, 0L, dynStrOff.toLong(), dynStr.length.toLong(), 0L)
        writeShdr(3, ".dynamic", 6, 0x3000L, dynOff.toLong(), dynBuf.size.toLong(), 16L)
        writeShdr(4, ".dynsym", 11, 0x4000L, symOff.toLong(), symBuf.size.toLong(), 24L)
        writeShdr(5, ".rodata", 1, 0x2000L, rodataOff.toLong(), rodataBytes.size.toLong(), 0L)
        writeShdr(6, ".text", 1, 0x1000L, textOff.toLong(), textBuf.size.toLong(), 0L)

        return buf.array()
    }

    private fun buildSyntheticFodDex(): ByteArray {
        val strings = listOf(
            "FOD_HBM_READY",
            "Lcom/android/systemui/biometrics/UdfpsController;",
            "Ljava/lang/Object;",
            "onFingerDown"
        )
        val stringDataOut = ByteArrayOutputStream()
        val stringOffsets = IntArray(strings.size)
        val stringIdsOff = 112
        val typeIdsOff = stringIdsOff + strings.size * 4
        val methodIdsOff = typeIdsOff + 2 * 4
        val classDefsOff = methodIdsOff + 8
        val dataBaseOff = classDefsOff + 32

        strings.forEachIndexed { idx, s ->
            stringOffsets[idx] = dataBaseOff + stringDataOut.size()
            val utf8 = s.toByteArray(StandardCharsets.UTF_8)
            stringDataOut.write(utf8.size) // single-byte uleb128 for short strings
            stringDataOut.write(utf8)
            stringDataOut.write(0)
        }

        // Dalvik code_item at dataBaseOff + stringDataOut.size() (aligned to 4)
        while (stringDataOut.size() % 4 != 0) stringDataOut.write(0)
        val codeOff = dataBaseOff + stringDataOut.size()
        val codeBuf = ByteBuffer.allocate(24).order(ByteOrder.LITTLE_ENDIAN).apply {
            putShort(2.toShort()) // registersSize
            putShort(1.toShort()) // insSize
            putShort(0.toShort()) // outsSize
            putShort(0.toShort()) // triesSize
            putInt(0)             // debugInfoOff
            putInt(3)             // insnsSize = 3 code units (const-string [2] + return-void [1])
            putShort(0x001A.toShort()) // const-string v0, string@0
            putShort(0.toShort())
            putShort(0x000E.toShort()) // return-void
        }.array()
        stringDataOut.write(codeBuf)

        // class_data_item right after code_item:
        // staticFields=0, instanceFields=0, directMethods=0, virtualMethods=1 -> method_idx_diff=0, access=1, codeOff=codeOff
        val classDataOff = dataBaseOff + stringDataOut.size()
        fun writeUleb(out: ByteArrayOutputStream, value: Int) {
            var v = value
            do {
                var b = v and 0x7F
                v = v ushr 7
                if (v != 0) b = b or 0x80
                out.write(b)
            } while (v != 0)
        }
        writeUleb(stringDataOut, 0) // staticFields
        writeUleb(stringDataOut, 0) // instanceFields
        writeUleb(stringDataOut, 0) // directMethods
        writeUleb(stringDataOut, 1) // virtualMethods
        writeUleb(stringDataOut, 0) // method_idx_diff = 0
        writeUleb(stringDataOut, 1) // accessFlags = PUBLIC
        writeUleb(stringDataOut, codeOff)

        val totalSize = dataBaseOff + stringDataOut.size()
        val buf = ByteBuffer.allocate(totalSize).order(ByteOrder.LITTLE_ENDIAN)
        buf.put("dex\n035\u0000".toByteArray(StandardCharsets.US_ASCII))
        buf.putInt(56, strings.size); buf.putInt(60, stringIdsOff)
        buf.putInt(64, 2); buf.putInt(68, typeIdsOff)
        buf.putInt(76, 0); buf.putInt(80, 0)
        buf.putInt(84, 1); buf.putInt(88, methodIdsOff)
        buf.putInt(96, 1); buf.putInt(100, classDefsOff)

        stringOffsets.forEachIndexed { idx, off -> buf.putInt(stringIdsOff + idx * 4, off) }
        // type_ids: 0 -> UdfpsController (str 1), 1 -> Object (str 2)
        buf.putInt(typeIdsOff, 1)
        buf.putInt(typeIdsOff + 4, 2)
        // method_ids[0]: class_idx=0, proto_idx=0, name_idx=3 ("onFingerDown")
        buf.putShort(methodIdsOff, 0.toShort())
        buf.putShort(methodIdsOff + 2, 0.toShort())
        buf.putInt(methodIdsOff + 4, 3)
        // class_defs[0]: class_idx=0, superclass_idx=1, class_data_off=classDataOff
        buf.putInt(classDefsOff, 0)
        buf.putInt(classDefsOff + 8, 1)
        buf.putInt(classDefsOff + 24, classDataOff)

        buf.position(dataBaseOff)
        buf.put(stringDataOut.toByteArray())
        return buf.array()
    }
}

