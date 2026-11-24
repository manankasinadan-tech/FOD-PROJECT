package com.example.fodtracer.core.disasm

import com.example.fodtracer.domain.interfaces.*
import com.example.fodtracer.domain.models.*
import com.example.fodtracer.system.shell.SafeShellExecutor

data class DeepArtifactOutput(
    val artifacts: List<DisassembledArtifact>,
    val rawFiles: Map<String, String>
)

/**
 * Exhaustive read-only extractor & disassembler that inspects every real ELF binary, vendor .so,
 * SystemUI/Framework APK/JAR, RRO overlay (AXML + resources.arsc), init .rc script, VINTF manifest,
 * and live /proc/<pid>/{fd,maps,stack,wchan,syscall} artifacts involved in FOD.
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

        val discoveredFilePaths = probeResults
            .flatMap { it.items }
            .map { it.location }
            .filter { it.startsWith("/") }
            .toMutableSet()

        runtimeSnapshots.forEach { snap ->
            discoveredFilePaths += snap.loadedFodLibraries
        }

        // Exhaustive directory scan across vendor/odm/system/product/system_ext/apex
        val extraRoots = listOf(
            "/vendor/etc/vintf",
            "/odm/etc/vintf",
            "/system_ext/etc/vintf",
            "/vendor/etc/init",
            "/odm/etc/init",
            "/system/etc/init",
            "/system_ext/etc/init",
            "/product/overlay",
            "/system_ext/overlay",
            "/vendor/overlay",
            "/odm/overlay",
            "/vendor/lib64/hw",
            "/vendor/lib/hw",
            "/vendor/bin/hw",
            "/odm/lib64/hw",
            "/odm/bin/hw"
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
                                p.contains("lhbm", true) || p.contains("touch", true) ||
                                p.contains("systemui", true) || p.contains("goodix", true) ||
                                p.contains("fpc", true) || p.contains("silead", true) ||
                                p.contains("focal", true) || p.contains("egis", true) ||
                                p.contains("composer", true) || p.endsWith("manifest.xml") ||
                                p.endsWith(".rc")
                            )
                    }
                    .take(80)
                    .forEach { discoveredFilePaths += it }
            }
        }

        // 1. Exhaustive ELF binary & shared library disassembly (probes + /proc/<pid>/maps)
        val elfCandidates = discoveredFilePaths.filter { path ->
            (path.contains("/bin/hw/") || path.endsWith(".so")) &&
                (path.contains("finger", true) || path.contains("biometric", true) ||
                    path.contains("goodix", true) || path.contains("fpc", true) ||
                    path.contains("silead", true) || path.contains("focal", true) ||
                    path.contains("egis", true) || path.contains("qbt", true) ||
                    path.contains("jiiov", true) || path.contains("udfps", true) ||
                    path.contains("fod", true) || path.contains("hbm", true) ||
                    path.contains("lhbm", true) || path.contains("composer", true) ||
                    path.contains("display", true) || path.contains("drm", true) ||
                    path.contains("surfaceflinger", true) || path.contains("touch", true))
        }.distinct().take(45)

        for (rawPath in elfCandidates) {
            val safePath = SafeSystemPath.parse(rawPath) ?: continue
            val bytes = safeShell?.readBinaryBytes(safePath, useRoot = allowRoot, maxBytes = 4_194_304)
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

        // 2. Exhaustive SystemUI, framework, services, APEX jars & RRO Overlay APKs
        val apkCandidates = buildList {
            discoveredFilePaths.filter {
                (it.endsWith(".apk", true) || it.endsWith(".jar", true)) &&
                    (it.contains("SystemUI", true) || it.contains("udfps", true) ||
                        it.contains("fod", true) || it.contains("overlay", true) ||
                        it.contains("biometric", true) || it.contains("fingerprint", true) ||
                        it.contains("framework-res", true) || it.contains("treble", true) ||
                        it.contains("phh", true))
            }.forEach { add(it) }
            add("/system/framework/services.jar")
            add("/system/framework/framework.jar")
            add("/system/framework/framework-res.apk")
            add("/system_ext/priv-app/SystemUI/SystemUI.apk")
            add("/system/priv-app/SystemUI/SystemUI.apk")
            add("/product/priv-app/SystemUI/SystemUI.apk")
        }.distinct().take(24)

        for (apkPath in apkCandidates) {
            val safePath = SafeSystemPath.parse(apkPath) ?: continue
            val maxCap = when {
                apkPath.contains("SystemUI", true) || apkPath.endsWith("services.jar") || apkPath.endsWith("framework.jar") -> 10_485_760
                apkPath.contains("framework-res", true) -> 8_388_608
                else -> 3_145_728
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

        // 3. Exhaustive init .rc, VINTF XML, and SELinux/permission XML extraction
        val textConfigPaths = discoveredFilePaths.filter {
            it.endsWith(".rc", true) || it.endsWith(".xml", true)
        }.distinct().take(40)

        for (cfgPath in textConfigPaths) {
            val safePath = SafeSystemPath.parse(cfgPath) ?: continue
            val read = shellExecutor.execute(
                ShellCommandSpec.ReadSystemFile(safePath),
                useRoot = allowRoot,
                timeoutMs = 2_000L,
                maxOutputBytes = 131_072
            )
            if (read.exitCode == 0 && read.stdout.isNotBlank()) {
                val isVintf = cfgPath.contains("vintf", true)
                val isRc = cfgPath.endsWith(".rc", true)
                val allLines = read.stdout.lineSequence().map { it.trimEnd() }.filter { it.isNotBlank() }.toList()
                val relevantLines = allLines.filter { line ->
                    val l = line.lowercase()
                    l.contains("finger") || l.contains("biometric") || l.contains("goodix") ||
                        l.contains("fpc") || l.contains("silead") || l.contains("focal") ||
                        l.contains("egis") || l.contains("udfps") || l.contains("fod") ||
                        l.contains("hbm") || l.contains("lhbm") || l.contains("service ") ||
                        l.contains("chown") || l.contains("chmod") || l.contains("on property") ||
                        l.contains("<name>") || l.contains("<fqname>") || l.contains("<hal")
                }

                if (relevantLines.isNotEmpty() || isVintf || isRc) {
                    val rawName = "disassembly/${cfgPath.trim('/').replace('/', '_')}.txt"
                    val fullContent = if (allLines.size <= 350) {
                        allLines.joinToString("\n")
                    } else {
                        relevantLines.take(250).joinToString("\n")
                    }
                    if (fullContent.isNotBlank()) {
                        rawFiles[rawName] = fullContent
                        val xrefs = relevantLines.filter {
                            it.contains("/dev/", true) || it.contains("/sys/", true) ||
                                it.contains("service ", true) || it.contains("<fqname>", true)
                        }.take(30)
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
                            extractedStrings = relevantLines.take(50),
                            disassemblySnippet = relevantLines.ifEmpty { allLines }.take(35).joinToString("\n"),
                            epistemicLevel = EpistemicLevel.PROVED,
                            rawFileName = rawName,
                            crossReferences = xrefs
                        )
                    }
                }
            }
        }

        // 4. Add runtime /proc/<pid>/{fd,maps,stack,wchan,syscall} artifacts if captured
        runtimeSnapshots.forEach { snap ->
            val lines = buildList {
                add("Process: ${snap.processName} (PID=${snap.pid})")
                snap.wchan?.let { add("wchan: $it") }
                snap.syscall?.let { add("syscall: $it") }
                if (snap.kernelStack.isNotEmpty()) {
                    add("[Kernel Stack (/proc/${snap.pid}/stack)]")
                    snap.kernelStack.forEach { add("  $it") }
                }
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
                    path = "/proc/${snap.pid}/{fd,maps,stack,wchan}",
                    partition = PartitionOrigin.KERNEL,
                    kind = ArtifactKind.PROC_RUNTIME,
                    neededLibraries = snap.loadedFodLibraries,
                    extractedStrings = snap.openFodDescriptors + snap.kernelStack,
                    disassemblySnippet = content,
                    epistemicLevel = snap.epistemicLevel,
                    rawFileName = rawName,
                    crossReferences = snap.kernelStack.take(20)
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
