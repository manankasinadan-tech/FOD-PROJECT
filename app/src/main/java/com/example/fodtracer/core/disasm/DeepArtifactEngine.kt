package com.example.fodtracer.core.disasm

import com.example.fodtracer.domain.interfaces.*
import com.example.fodtracer.domain.models.*
import com.example.fodtracer.system.shell.SafeShellExecutor

data class DeepArtifactOutput(
    val artifacts: List<DisassembledArtifact>,
    val rawFiles: Map<String, String>
)

/**
 * Deep read-only extractor & disassembler that inspects every real ELF binary, vendor .so,
 * SystemUI/Framework APK/JAR, RRO overlay, init .rc script, and VINTF manifest involved in FOD.
 */
class DeepArtifactEngine(
    private val shellExecutor: ShellExecutor
) {

    suspend fun inspectAll(
        probeResults: List<ProbeResult>,
        runtimeSnapshots: List<ProcessRuntimeSnapshot>,
        allowRoot: Boolean
    ): DeepArtifactOutput {
        val safeShell = shellExecutor as? SafeShellExecutor
        val artifacts = mutableListOf<DisassembledArtifact>()
        val rawFiles = linkedMapOf<String, String>()
        var idx = 0

        fun nextId(tag: String): String {
            idx++
            return "DIS-$tag-${idx.toString().padStart(3, '0')}"
        }

        // 1. Gather candidate ELF paths from HAL/Vendor probes + live /proc/<pid>/maps
        val discoveredFilePaths = probeResults
            .flatMap { it.items }
            .map { it.location }
            .filter { it.startsWith("/") }
            .toMutableSet()

        runtimeSnapshots.forEach { snap ->
            discoveredFilePaths += snap.loadedFodLibraries
        }

        // Actively scan overlay & framework directories too
        val extraRoots = listOf(
            "/vendor/etc/vintf",
            "/odm/etc/vintf",
            "/vendor/etc/init",
            "/odm/etc/init",
            "/product/overlay",
            "/system_ext/overlay",
            "/vendor/overlay"
        )
        for (root in extraRoots) {
            val safeRoot = SafeSystemPath.parse(root) ?: continue
            val ls = shellExecutor.execute(
                ShellCommandSpec.ListSystemDir(safeRoot, maxDepth = 3),
                useRoot = allowRoot,
                timeoutMs = 2_500L
            )
            if (ls.exitCode == 0) {
                ls.stdout.lineSequence()
                    .map { it.trim() }
                    .filter { p ->
                        p.isNotEmpty() && (
                            p.contains("finger", true) || p.contains("biometric", true) ||
                                p.contains("udfps", true) || p.contains("fod", true) ||
                                p.contains("display", true) || p.contains("hbm", true) ||
                                p.contains("touch", true) || p.contains("systemui", true) ||
                                p.endsWith("manifest.xml")
                            )
                    }
                    .take(25)
                    .forEach { discoveredFilePaths += it }
            }
        }

        val elfCandidates = discoveredFilePaths.filter { path ->
            (path.contains("/bin/hw/") || path.endsWith(".so")) &&
                (path.contains("finger", true) || path.contains("biometric", true) ||
                    path.contains("goodix", true) || path.contains("fpc", true) ||
                    path.contains("silead", true) || path.contains("focal", true) ||
                    path.contains("egis", true) || path.contains("udfps", true) ||
                    path.contains("fod", true) || path.contains("hbm", true) ||
                    path.contains("composer", true) || path.contains("display", true))
        }.distinct().take(12)

        for (rawPath in elfCandidates) {
            val safePath = SafeSystemPath.parse(rawPath) ?: continue
            val bytes = safeShell?.readBinaryBytes(safePath, useRoot = allowRoot, maxBytes = 2_621_440)
            if (bytes != null) {
                val analyzed = ElfDisassembler.analyze(
                    id = nextId("ELF"),
                    path = rawPath,
                    partition = inferPartition(rawPath),
                    bytes = bytes
                )
                if (analyzed != null) {
                    artifacts += analyzed.first
                    analyzed.first.rawFileName?.let { rawFiles[it] = analyzed.second }
                }
            }
        }

        // 2. Analyze SystemUI APK, services.jar, framework-res.apk, and RRO Overlay APKs
        val apkCandidates = buildList {
            discoveredFilePaths.filter {
                it.endsWith(".apk", true) &&
                    (it.contains("SystemUI", true) || it.contains("udfps", true) ||
                        it.contains("fod", true) || it.contains("overlay", true) ||
                        it.contains("biometric", true) || it.contains("framework-res", true))
            }.forEach { add(it) }
            add("/system/framework/services.jar")
        }.distinct().take(8)

        for (apkPath in apkCandidates) {
            val safePath = SafeSystemPath.parse(apkPath) ?: continue
            val maxCap = if (apkPath.contains("SystemUI", true) || apkPath.endsWith("services.jar")) {
                5_242_880
            } else {
                2_097_152
            }
            val bytes = safeShell?.readBinaryBytes(safePath, useRoot = allowRoot, maxBytes = maxCap)
            if (bytes != null) {
                val isOverlay = apkPath.contains("overlay", true)
                val analyzed = DexAndApkDisassembler.analyzeApkOrJar(
                    id = nextId(if (isOverlay) "RRO" else "DEX"),
                    path = apkPath,
                    partition = inferPartition(apkPath),
                    isOverlay = isOverlay,
                    zipBytes = bytes
                )
                if (analyzed != null) {
                    artifacts += analyzed.first
                    analyzed.first.rawFileName?.let { rawFiles[it] = analyzed.second }
                }
            }
        }

        // 3. Read & extract init .rc and VINTF XML manifests
        val textConfigPaths = discoveredFilePaths.filter {
            it.endsWith(".rc", true) || it.endsWith(".xml", true)
        }.distinct().take(12)

        for (cfgPath in textConfigPaths) {
            val safePath = SafeSystemPath.parse(cfgPath) ?: continue
            val read = shellExecutor.execute(
                ShellCommandSpec.ReadSystemFile(safePath),
                useRoot = allowRoot,
                timeoutMs = 2_000L,
                maxOutputBytes = 65_536
            )
            if (read.exitCode == 0 && read.stdout.isNotBlank()) {
                val isVintf = cfgPath.contains("vintf", true)
                val isRc = cfgPath.endsWith(".rc", true)
                val relevantLines = read.stdout.lineSequence()
                    .map { it.trim() }
                    .filter { line ->
                        line.isNotEmpty() && (
                            line.contains("finger", true) || line.contains("biometric", true) ||
                                line.contains("goodix", true) || line.contains("fpc", true) ||
                                line.contains("udfps", true) || line.contains("fod", true) ||
                                line.contains("hbm", true) || line.contains("service ", true) ||
                                line.contains("chown", true) || line.contains("chmod", true) ||
                                line.contains("<name>", true) || line.contains("<fqname>", true)
                            )
                    }
                    .take(80)
                    .toList()

                if (relevantLines.isNotEmpty()) {
                    val rawName = "disassembly/${cfgPath.trim('/').replace('/', '_')}.txt"
                    val fullContent = relevantLines.joinToString("\n")
                    rawFiles[rawName] = fullContent
                    artifacts += DisassembledArtifact(
                        id = nextId(if (isVintf) "VINTF" else if (isRc) "RC" else "CFG"),
                        name = cfgPath.substringAfterLast('/'),
                        path = cfgPath,
                        partition = inferPartition(cfgPath),
                        kind = when {
                            isVintf -> ArtifactKind.VINTF_XML
                            isRc -> ArtifactKind.INIT_RC
                            else -> ArtifactKind.SEPOLICY_OR_PERM
                        },
                        extractedStrings = relevantLines.take(30),
                        disassemblySnippet = relevantLines.take(25).joinToString("\n"),
                        epistemicLevel = EpistemicLevel.PROVED,
                        rawFileName = rawName
                    )
                }
            }
        }

        // 4. Add runtime /proc/<pid>/fd & maps artifacts if captured
        runtimeSnapshots.forEach { snap ->
            val lines = buildList {
                add("Process: ${snap.processName} (PID=${snap.pid})")
                if (snap.openFodDescriptors.isNotEmpty()) {
                    add("[Open /proc/${snap.pid}/fd FOD/Display/Device handles]")
                    snap.openFodDescriptors.forEach { add("  $it") }
                }
                if (snap.loadedFodLibraries.isNotEmpty()) {
                    add("[Loaded /proc/${snap.pid}/maps libraries & APKs]")
                    snap.loadedFodLibraries.forEach { add("  $it") }
                }
            }
            if (lines.size > 1) {
                val rawName = "disassembly/proc_${snap.pid}_${snap.processName.replace('/', '_')}.txt"
                val content = lines.joinToString("\n")
                rawFiles[rawName] = content
                artifacts += DisassembledArtifact(
                    id = nextId("PROC"),
                    name = "${snap.processName} (PID ${snap.pid})",
                    path = "/proc/${snap.pid}/fd & maps",
                    partition = PartitionOrigin.KERNEL,
                    kind = ArtifactKind.PROC_RUNTIME,
                    neededLibraries = snap.loadedFodLibraries,
                    extractedStrings = snap.openFodDescriptors,
                    disassemblySnippet = content,
                    epistemicLevel = snap.epistemicLevel,
                    rawFileName = rawName
                )
            }
        }

        return DeepArtifactOutput(artifacts = artifacts, rawFiles = rawFiles)
    }

    private fun inferPartition(location: String): PartitionOrigin = when {
        location.startsWith("/vendor") -> PartitionOrigin.VENDOR
        location.startsWith("/odm") -> PartitionOrigin.ODM
        location.startsWith("/system_ext") -> PartitionOrigin.SYSTEM_EXT
        location.startsWith("/product") -> PartitionOrigin.PRODUCT
        location.startsWith("/apex") -> PartitionOrigin.APEX
        location.startsWith("/sys") || location.startsWith("/proc") || location.startsWith("/dev") -> PartitionOrigin.KERNEL
        location.startsWith("/system") -> PartitionOrigin.SYSTEM
        else -> PartitionOrigin.UNKNOWN
    }
}
