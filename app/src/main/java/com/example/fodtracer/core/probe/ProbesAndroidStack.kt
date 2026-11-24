package com.example.fodtracer.core.probe

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import com.example.fodtracer.domain.interfaces.*
import com.example.fodtracer.domain.models.*
import com.example.fodtracer.system.biometrics.AndroidBiometricInspector

class BiometricProbe(private val androidContext: Context) : FodProbe {
    override val probeId: String = "probe_biometric"
    override val domain: ProbeDomain = ProbeDomain.BIOMETRIC

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val items = mutableListOf<ProbeFindingItem>()
        val inaccessible = mutableListOf<String>()

        val bioApi = AndroidBiometricInspector(androidContext).inspectBiometricState()
        items += ProbeFindingItem(
            key = "biometric.api_status",
            value = bioApi.statusCodeLabel,
            location = "BiometricManager",
            discoveryStatus = DiscoveryStatus.FOUND,
            epistemicLevel = EpistemicLevel.PROVED,
            accessLevel = AccessLevel.ANDROID_API
        )

        val fpDump = context.shellExecutor.execute(
            ShellCommandSpec.Dumpsys(AllowedDumpsysService.FINGERPRINT),
            useRoot = context.allowRoot
        )
        parseDumpsysSection(fpDump, "dumpsys fingerprint", items, inaccessible)

        val bioDump = context.shellExecutor.execute(
            ShellCommandSpec.Dumpsys(AllowedDumpsysService.BIOMETRIC),
            useRoot = context.allowRoot
        )
        parseDumpsysSection(bioDump, "dumpsys biometric", items, inaccessible)

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = when {
                items.any { it.key.startsWith("dumpsys") && it.discoveryStatus == DiscoveryStatus.FOUND } -> DiscoveryStatus.FOUND
                inaccessible.isNotEmpty() -> DiscoveryStatus.PARTIAL
                else -> DiscoveryStatus.PARTIAL
            },
            accessLevelUsed = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.ANDROID_API,
            summary = "Biometric API + dumpsys inspection (${items.size} findings).",
            items = items,
            inaccessibleReasons = inaccessible,
            rawFileName = if (fpDump.stdout.isNotBlank() || bioDump.stdout.isNotBlank()) "raw/dumpsys_biometric.txt" else null,
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }

    private fun parseDumpsysSection(
        res: ShellExecutionResult,
        sourceName: String,
        items: MutableList<ProbeFindingItem>,
        inaccessible: MutableList<String>
    ) {
        if (res.exitCode != 0 || res.stdout.isBlank()) {
            val reason = if (res.denied) "$sourceName permission denied (requires Root or DUMP)" else "$sourceName unavailable (${res.stderr.ifBlank { "empty" }})"
            inaccessible += reason
            items += ProbeFindingItem(
                key = "$sourceName.access",
                value = reason,
                location = sourceName,
                discoveryStatus = if (res.denied) DiscoveryStatus.INACCESSIBLE else DiscoveryStatus.ERROR,
                epistemicLevel = EpistemicLevel.INACCESSIBLE,
                accessLevel = if (res.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
            )
            return
        }

        val keywords = listOf(
            "sensor", "udfps", "fod", "optical", "ultrasonic", "location", "radius",
            "strength", "authenticator", "enrolled", "hal", "aidl", "hidl", "state", "lockout"
        )
        val interestingLines = res.stdout.lineSequence()
            .map { it.trim() }
            .filter { line -> line.isNotEmpty() && keywords.any { line.contains(it, ignoreCase = true) } }
            .take(60)
            .toList()

        interestingLines.forEachIndexed { idx, line ->
            items += ProbeFindingItem(
                key = "$sourceName.line.$idx",
                value = line.take(260),
                location = sourceName,
                discoveryStatus = DiscoveryStatus.FOUND,
                epistemicLevel = EpistemicLevel.PROVED,
                accessLevel = if (res.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
            )
        }
        if (interestingLines.isEmpty()) {
            items += ProbeFindingItem(
                key = "$sourceName.summary",
                value = res.stdout.trim().take(240),
                location = sourceName,
                discoveryStatus = DiscoveryStatus.FOUND,
                epistemicLevel = EpistemicLevel.PROVED,
                accessLevel = if (res.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
            )
        }
    }
}

class FrameworkProbe : FodProbe {
    override val probeId: String = "probe_framework"
    override val domain: ProbeDomain = ProbeDomain.FRAMEWORK

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val items = mutableListOf<ProbeFindingItem>()
        val inaccessible = mutableListOf<String>()

        val svcRes = context.shellExecutor.execute(ShellCommandSpec.ServiceList, useRoot = context.allowRoot)
        if (svcRes.exitCode == 0 && svcRes.stdout.isNotBlank()) {
            val bioKeywords = listOf(
                "fingerprint", "biometric", "auth", "display", "surfaceflinger",
                "input", "overlay", "udfps", "fod", "face", "power"
            )
            svcRes.stdout.lineSequence()
                .filter { line -> bioKeywords.any { kw -> line.contains(kw, ignoreCase = true) } }
                .take(80)
                .forEachIndexed { idx, line ->
                    items += ProbeFindingItem(
                        key = "binder.service.$idx",
                        value = line.trim().take(220),
                        location = "service list",
                        discoveryStatus = DiscoveryStatus.FOUND,
                        epistemicLevel = EpistemicLevel.PROVED,
                        accessLevel = if (svcRes.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                    )
                }
        } else {
            inaccessible += "service list blocked: ${svcRes.stderr.ifBlank { "exit ${svcRes.exitCode}" }}"
        }

        // Check framework-res APK presence
        val fwPath = SafeSystemPath.parse("/system/framework/framework-res.apk")
        if (fwPath != null) {
            val fwDir = SafeSystemPath.parse("/system/framework")
            if (fwDir != null) {
                val ls = context.shellExecutor.execute(ShellCommandSpec.ListSystemDir(fwDir, 1), useRoot = context.allowRoot)
                if (ls.exitCode == 0 && ls.stdout.contains("framework-res")) {
                    items += ProbeFindingItem(
                        key = "framework.resources_apk",
                        value = "/system/framework/framework-res.apk present",
                        location = "/system/framework/framework-res.apk",
                        discoveryStatus = DiscoveryStatus.FOUND,
                        epistemicLevel = EpistemicLevel.PROVED,
                        accessLevel = if (ls.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                    )
                }
            }
        }

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = if (items.isNotEmpty()) DiscoveryStatus.FOUND else DiscoveryStatus.PARTIAL,
            accessLevelUsed = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL,
            summary = "Framework binder & resource scan (${items.size} items).",
            items = items,
            inaccessibleReasons = inaccessible,
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }
}

class SystemUiProbe(private val androidContext: Context) : FodProbe {
    override val probeId: String = "probe_systemui"
    override val domain: ProbeDomain = ProbeDomain.SYSTEMUI

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val items = mutableListOf<ProbeFindingItem>()
        val pm = androidContext.packageManager

        val packages = runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                pm.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
            } else {
                @Suppress("DEPRECATION")
                pm.getInstalledPackages(0)
            }
        }.getOrDefault(emptyList())

        val relevantKeywords = listOf(
            "systemui", "biometric", "fingerprint", "udfps", "fod",
            "overlay", "treble", "phh", "goodix", "fpc"
        )
        packages.filter { pkg ->
            relevantKeywords.any { kw -> pkg.packageName.contains(kw, ignoreCase = true) }
        }.take(60).forEach { pkg ->
            val srcDir = pkg.applicationInfo?.sourceDir ?: "unknown"
            items += ProbeFindingItem(
                key = "package.${pkg.packageName}",
                value = "version=${pkg.versionName ?: "?"} path=$srcDir",
                location = srcDir,
                discoveryStatus = DiscoveryStatus.FOUND,
                epistemicLevel = EpistemicLevel.PROVED,
                accessLevel = AccessLevel.ANDROID_API
            )
        }

        // Inspect recent logcat for UdfpsController / AuthController / BiometricPrompt hints
        val logRes = context.shellExecutor.execute(
            ShellCommandSpec.LogcatSnapshot(listOf("main", "system"), lines = 350),
            useRoot = context.allowRoot
        )
        val inaccessible = mutableListOf<String>()
        if (logRes.exitCode == 0 && logRes.stdout.isNotBlank()) {
            val sysUiLines = logRes.stdout.lineSequence()
                .filter { line ->
                    line.contains("Udfps", ignoreCase = true) ||
                        line.contains("AuthController", ignoreCase = true) ||
                        line.contains("Biometric", ignoreCase = true) ||
                        line.contains("Fingerprint", ignoreCase = true)
                }
                .take(30)
                .toList()
            sysUiLines.forEachIndexed { idx, line ->
                items += ProbeFindingItem(
                    key = "systemui.log_signal.$idx",
                    value = line.trim().take(240),
                    location = "logcat(main/system)",
                    discoveryStatus = DiscoveryStatus.FOUND,
                    epistemicLevel = EpistemicLevel.PROVED,
                    accessLevel = if (logRes.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                )
            }
        } else if (logRes.denied) {
            inaccessible += "logcat denied without READ_LOGS or Root."
        }

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = if (items.isNotEmpty()) DiscoveryStatus.FOUND else DiscoveryStatus.PARTIAL,
            accessLevelUsed = AccessLevel.ANDROID_API,
            summary = "SystemUI & biometric package discovery (${items.size} items).",
            items = items,
            inaccessibleReasons = inaccessible,
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }
}

class OverlayProbe : FodProbe {
    override val probeId: String = "probe_overlay"
    override val domain: ProbeDomain = ProbeDomain.OVERLAY

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val items = mutableListOf<ProbeFindingItem>()
        val inaccessible = mutableListOf<String>()

        val overlayRes = context.shellExecutor.execute(
            ShellCommandSpec.CmdOverlayList(0),
            useRoot = context.allowRoot
        )
        if (overlayRes.exitCode == 0 && overlayRes.stdout.isNotBlank()) {
            val relevantKeywords = listOf(
                "udfps", "fod", "finger", "biometric", "systemui", "framework",
                "treble", "phh", "display", "brightness", "doze", "aod"
            )
            var currentTarget = "unknown"
            overlayRes.stdout.lineSequence().forEach { rawLine ->
                val line = rawLine.trim()
                if (line.isEmpty()) return@forEach
                if (!line.startsWith("[")) {
                    currentTarget = line
                } else if (relevantKeywords.any { line.contains(it, ignoreCase = true) || currentTarget.contains(it, ignoreCase = true) }) {
                    val enabled = line.startsWith("[x]")
                    val pkg = line.removePrefix("[x]").removePrefix("[ ]").trim()
                    items += ProbeFindingItem(
                        key = "overlay.$pkg",
                        value = "enabled=$enabled target=$currentTarget",
                        location = "cmd overlay list",
                        discoveryStatus = DiscoveryStatus.FOUND,
                        epistemicLevel = EpistemicLevel.PROVED,
                        accessLevel = if (overlayRes.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                    )
                }
            }
        } else {
            inaccessible += "cmd overlay list inaccessible (${overlayRes.stderr.ifBlank { "exit ${overlayRes.exitCode}" }})"
            val dumpsysOverlay = context.shellExecutor.execute(
                ShellCommandSpec.Dumpsys(AllowedDumpsysService.OVERLAY),
                useRoot = context.allowRoot
            )
            if (dumpsysOverlay.exitCode == 0 && dumpsysOverlay.stdout.isNotBlank()) {
                dumpsysOverlay.stdout.lineSequence()
                    .filter { it.contains("udfps", true) || it.contains("fod", true) || it.contains("systemui", true) || it.contains("treble", true) }
                    .take(40)
                    .forEachIndexed { idx, line ->
                        items += ProbeFindingItem(
                            key = "overlay.dump.$idx",
                            value = line.trim().take(240),
                            location = "dumpsys overlay",
                            discoveryStatus = DiscoveryStatus.FOUND,
                            epistemicLevel = EpistemicLevel.PROVED,
                            accessLevel = if (dumpsysOverlay.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                        )
                    }
            } else if (dumpsysOverlay.denied) {
                inaccessible += "dumpsys overlay denied."
            }
        }

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = if (items.isNotEmpty()) DiscoveryStatus.FOUND else if (inaccessible.isNotEmpty()) DiscoveryStatus.INACCESSIBLE else DiscoveryStatus.NOT_FOUND,
            accessLevelUsed = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL,
            summary = "RRO Overlay inspection (${items.size} relevant overlays).",
            items = items.take(120),
            inaccessibleReasons = inaccessible,
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }
}
