package com.example.fodtracer.core.probe

import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.view.WindowManager
import com.example.fodtracer.domain.interfaces.*
import com.example.fodtracer.domain.models.*
import com.example.fodtracer.system.selinux.SeLinuxInspector

class PropertiesProbe : FodProbe {
    override val probeId: String = "probe_properties"
    override val domain: ProbeDomain = ProbeDomain.PROPERTIES

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val res = context.shellExecutor.execute(ShellCommandSpec.GetPropAll, useRoot = false)
        if (res.exitCode != 0 && res.stdout.isBlank()) {
            return ProbeResult(
                probeId = probeId,
                domain = domain,
                status = if (res.denied) DiscoveryStatus.INACCESSIBLE else DiscoveryStatus.ERROR,
                accessLevelUsed = AccessLevel.UNPRIVILEGED_SHELL,
                summary = "getprop failed: ${res.stderr.ifBlank { "exit ${res.exitCode}" }}",
                items = emptyList(),
                inaccessibleReasons = listOf(res.stderr.ifBlank { "getprop unavailable" }),
                durationMs = System.currentTimeMillis() - start,
                civilTimestampMs = System.currentTimeMillis()
            )
        }

        val items = mutableListOf<ProbeFindingItem>()
        val relevantPrefixesOrKeywords = listOf(
            "fp", "finger", "biometric", "udfps", "fod", "goodix", "fpc", "silead", "focal",
            "egis", "qbt", "hbm", "lhbm", "dim", "touch", "treble", "vndk", "gsi", "phh",
            "lineage", "crdroid", "evolution", "pixel", "miui", "hyperos", "oplus", "oneplus",
            "ro.product", "ro.build.fingerprint", "ro.build.display", "ro.hardware", "ro.soc"
        )

        val propRegex = Regex("^\\[([^\\]]+)]: \\[(.*)]$")
        res.stdout.lineSequence().forEach { line ->
            val match = propRegex.matchEntire(line.trim()) ?: return@forEach
            val key = match.groupValues[1]
            val value = match.groupValues[2]
            val isRelevant = relevantPrefixesOrKeywords.any { kw ->
                key.contains(kw, ignoreCase = true) || value.contains(kw, ignoreCase = true)
            }
            if (isRelevant) {
                items += ProbeFindingItem(
                    key = key,
                    value = value,
                    location = "system_property:$key",
                    discoveryStatus = DiscoveryStatus.FOUND,
                    epistemicLevel = EpistemicLevel.PROVED,
                    accessLevel = AccessLevel.UNPRIVILEGED_SHELL
                )
            }
        }

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = if (items.isNotEmpty()) DiscoveryStatus.FOUND else DiscoveryStatus.PARTIAL,
            accessLevelUsed = AccessLevel.UNPRIVILEGED_SHELL,
            summary = "${items.size} relevant system/vendor/FOD properties extracted.",
            items = items.take(250),
            rawFileName = "raw/getprop_filtered.txt",
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }
}

class HardwareProbe(private val androidContext: Context) : FodProbe {
    override val probeId: String = "probe_hardware"
    override val domain: ProbeDomain = ProbeDomain.HARDWARE

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val items = mutableListOf<ProbeFindingItem>()

        items += ProbeFindingItem(
            key = "device.model",
            value = "${Build.MANUFACTURER} ${Build.MODEL} (${Build.DEVICE})",
            location = "android.os.Build",
            discoveryStatus = DiscoveryStatus.FOUND,
            epistemicLevel = EpistemicLevel.PROVED,
            accessLevel = AccessLevel.ANDROID_API
        )
        items += ProbeFindingItem(
            key = "device.hardware_board",
            value = "hardware=${Build.HARDWARE}, board=${Build.BOARD}",
            location = "android.os.Build",
            discoveryStatus = DiscoveryStatus.FOUND,
            epistemicLevel = EpistemicLevel.PROVED,
            accessLevel = AccessLevel.ANDROID_API
        )

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            items += ProbeFindingItem(
                key = "device.soc",
                value = "${Build.SOC_MANUFACTURER} ${Build.SOC_MODEL}",
                location = "android.os.Build.SOC_*",
                discoveryStatus = DiscoveryStatus.FOUND,
                epistemicLevel = EpistemicLevel.PROVED,
                accessLevel = AccessLevel.ANDROID_API
            )
        }

        val pm = androidContext.packageManager
        val fpFeature = pm.hasSystemFeature(PackageManager.FEATURE_FINGERPRINT)
        items += ProbeFindingItem(
            key = "feature.fingerprint",
            value = fpFeature.toString(),
            location = "PackageManager.FEATURE_FINGERPRINT",
            discoveryStatus = if (fpFeature) DiscoveryStatus.FOUND else DiscoveryStatus.NOT_FOUND,
            epistemicLevel = EpistemicLevel.PROVED,
            accessLevel = AccessLevel.ANDROID_API
        )

        runCatching {
            val wm = androidContext.getSystemService(WindowManager::class.java)
            val display = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                androidContext.display ?: wm?.defaultDisplay
            } else {
                @Suppress("DEPRECATION")
                wm?.defaultDisplay
            }
            if (display != null) {
                val mode = display.mode
                items += ProbeFindingItem(
                    key = "display.mode",
                    value = "${mode.physicalWidth}x${mode.physicalHeight} @ ${mode.refreshRate}Hz",
                    location = "android.view.Display.Mode",
                    discoveryStatus = DiscoveryStatus.FOUND,
                    epistemicLevel = EpistemicLevel.PROVED,
                    accessLevel = AccessLevel.ANDROID_API
                )
            }
        }

        val inaccessible = mutableListOf<String>()
        val socPaths = listOf("/sys/devices/soc0/soc_id", "/sys/devices/soc0/family", "/proc/cpuinfo")
        for (rawPath in socPaths) {
            val safePath = SafeSystemPath.parse(rawPath) ?: continue
            val read = context.shellExecutor.execute(
                ShellCommandSpec.ReadSystemFile(safePath),
                useRoot = context.allowRoot
            )
            if (read.exitCode == 0 && read.stdout.isNotBlank()) {
                val snippet = read.stdout.lineSequence().take(8).joinToString(" | ").take(240)
                items += ProbeFindingItem(
                    key = "sysfs.${rawPath.substringAfterLast('/')}",
                    value = snippet,
                    location = rawPath,
                    discoveryStatus = DiscoveryStatus.FOUND,
                    epistemicLevel = EpistemicLevel.PROVED,
                    accessLevel = if (read.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                )
            } else if (read.denied) {
                inaccessible += "$rawPath (${read.stderr.ifBlank { "permission denied" }})"
                items += ProbeFindingItem(
                    key = "sysfs.${rawPath.substringAfterLast('/')}",
                    value = "Access denied",
                    location = rawPath,
                    discoveryStatus = DiscoveryStatus.INACCESSIBLE,
                    epistemicLevel = EpistemicLevel.INACCESSIBLE,
                    accessLevel = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                )
            }
        }

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = if (inaccessible.isEmpty()) DiscoveryStatus.FOUND else DiscoveryStatus.PARTIAL,
            accessLevelUsed = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.ANDROID_API,
            summary = "Hardware profile collected (${items.size} items).",
            items = items,
            inaccessibleReasons = inaccessible,
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }
}

class SeLinuxProbe(private val inspector: SeLinuxInspector) : FodProbe {
    override val probeId: String = "probe_selinux"
    override val domain: ProbeDomain = ProbeDomain.SELINUX

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val res = inspector.inspect(useRoot = context.allowRoot)
        val items = mutableListOf<ProbeFindingItem>()
        val inaccessible = mutableListOf<String>()

        items += ProbeFindingItem(
            key = "selinux.mode",
            value = res.mode.name,
            location = "/sys/fs/selinux/enforce / getenforce",
            discoveryStatus = if (res.mode != SeLinuxMode.UNKNOWN) DiscoveryStatus.FOUND else DiscoveryStatus.INACCESSIBLE,
            epistemicLevel = if (res.mode != SeLinuxMode.UNKNOWN) EpistemicLevel.PROVED else EpistemicLevel.INACCESSIBLE,
            accessLevel = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
        )

        res.context?.let { ctx ->
            items += ProbeFindingItem(
                key = "selinux.context",
                value = ctx,
                location = "id -Z",
                discoveryStatus = DiscoveryStatus.FOUND,
                epistemicLevel = EpistemicLevel.PROVED,
                accessLevel = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
            )
        }

        res.avcDenials.forEachIndexed { idx, denial ->
            items += ProbeFindingItem(
                key = "selinux.avc_denial.$idx",
                value = denial,
                location = "logcat/dmesg",
                discoveryStatus = DiscoveryStatus.FOUND,
                epistemicLevel = EpistemicLevel.PROVED,
                accessLevel = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
            )
        }

        res.accessLimitedNote?.let { inaccessible += it }

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = if (inaccessible.isEmpty()) DiscoveryStatus.FOUND else DiscoveryStatus.PARTIAL,
            accessLevelUsed = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL,
            summary = "SELinux=${res.mode.name}, ${res.avcDenials.size} FOD-related AVC denials observed.",
            items = items,
            inaccessibleReasons = inaccessible,
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }
}
