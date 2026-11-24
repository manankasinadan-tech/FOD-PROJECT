package com.example.fodtracer.core.probe

import com.example.fodtracer.domain.interfaces.*
import com.example.fodtracer.domain.models.*

private val FOD_HAL_KEYWORDS = listOf(
    "fingerprint", "biometric", "udfps", "fod", "goodix", "fpc", "silead",
    "focaltech", "egis", "chipone", "jiiov", "qbt", "cdfinger", "sunwave"
)

private val DISPLAY_FOD_KEYWORDS = listOf(
    "hbm", "lhbm", "fod", "dim", "backlight", "brightness", "max_brightness",
    "aod", "doze", "panel", "drm", "oled", "fp_", "udfps", "local_hbm"
)

private val TOUCH_KERNEL_KEYWORDS = listOf(
    "touch", "tp_", "fod", "udfps", "fingerprint", "goodix", "fpc", "focal",
    "synaptics", "novatek", "ilitek", "himax", "fts", "sec_ts", "xiaomi_touch", "oplus_tp"
)

internal suspend fun scanBoundedPaths(
    context: ProbeContext,
    roots: List<String>,
    maxDepth: Int,
    keywords: List<String>,
    keyPrefix: String,
    items: MutableList<ProbeFindingItem>,
    inaccessible: MutableList<String>
) {
    for (rawRoot in roots) {
        val safeRoot = SafeSystemPath.parse(rawRoot) ?: continue
        val res = context.shellExecutor.execute(
            ShellCommandSpec.ListSystemDir(safeRoot, maxDepth = maxDepth),
            useRoot = context.allowRoot,
            timeoutMs = 3_000L
        )
        if (res.exitCode != 0 && res.stdout.isBlank()) {
            if (res.denied || res.stderr.contains("permission denied", ignoreCase = true)) {
                inaccessible += "$rawRoot (${res.stderr.ifBlank { "access denied" }})"
            }
            continue
        }
        val matched = res.stdout.lineSequence()
            .map { it.trim() }
            .filter { path ->
                path.isNotEmpty() && keywords.any { kw -> path.contains(kw, ignoreCase = true) }
            }
            .distinct()
            .take(50)
            .toList()

        matched.forEachIndexed { idx, matchedPath ->
            items += ProbeFindingItem(
                key = "$keyPrefix.${rawRoot.trim('/').replace('/', '_')}.$idx",
                value = matchedPath,
                location = matchedPath,
                discoveryStatus = DiscoveryStatus.FOUND,
                epistemicLevel = EpistemicLevel.PROVED,
                accessLevel = if (res.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
            )
        }
    }
}

class HalProbe : FodProbe {
    override val probeId: String = "probe_hal"
    override val domain: ProbeDomain = ProbeDomain.HAL

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val items = mutableListOf<ProbeFindingItem>()
        val inaccessible = mutableListOf<String>()

        val lshal = context.shellExecutor.execute(ShellCommandSpec.LshalList, useRoot = context.allowRoot)
        if (lshal.exitCode == 0 && lshal.stdout.isNotBlank()) {
            lshal.stdout.lineSequence()
                .filter { line ->
                    FOD_HAL_KEYWORDS.any { line.contains(it, ignoreCase = true) } ||
                        line.contains("composer", ignoreCase = true) ||
                        line.contains("display", ignoreCase = true)
                }
                .take(60)
                .forEachIndexed { idx, line ->
                    items += ProbeFindingItem(
                        key = "hal.lshal.$idx",
                        value = line.trim().take(240),
                        location = "lshal",
                        discoveryStatus = DiscoveryStatus.FOUND,
                        epistemicLevel = EpistemicLevel.PROVED,
                        accessLevel = if (lshal.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                    )
                }
        } else {
            inaccessible += "lshal inaccessible: ${lshal.stderr.ifBlank { "exit ${lshal.exitCode}" }}"
        }

        scanBoundedPaths(
            context = context,
            roots = listOf(
                "/vendor/bin/hw",
                "/vendor/lib64/hw",
                "/vendor/lib/hw",
                "/odm/bin/hw",
                "/odm/lib64/hw",
                "/system_ext/lib64"
            ),
            maxDepth = 2,
            keywords = FOD_HAL_KEYWORDS,
            keyPrefix = "hal.binary",
            items = items,
            inaccessible = inaccessible
        )

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = when {
                items.isNotEmpty() && inaccessible.isEmpty() -> DiscoveryStatus.FOUND
                items.isNotEmpty() -> DiscoveryStatus.PARTIAL
                inaccessible.isNotEmpty() -> DiscoveryStatus.INACCESSIBLE
                else -> DiscoveryStatus.NOT_FOUND
            },
            accessLevelUsed = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL,
            summary = "HAL AIDL/HIDL & native binary discovery (${items.size} items).",
            items = items.take(120),
            inaccessibleReasons = inaccessible,
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }
}

class VendorProbe : FodProbe {
    override val probeId: String = "probe_vendor"
    override val domain: ProbeDomain = ProbeDomain.VENDOR

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val items = mutableListOf<ProbeFindingItem>()
        val inaccessible = mutableListOf<String>()

        scanBoundedPaths(
            context = context,
            roots = listOf(
                "/vendor/etc/vintf",
                "/odm/etc/vintf",
                "/vendor/etc/init",
                "/odm/etc/init",
                "/vendor/lib64",
                "/vendor/etc/permissions"
            ),
            maxDepth = 2,
            keywords = FOD_HAL_KEYWORDS + listOf("display", "touch", "biometrics"),
            keyPrefix = "vendor.artifact",
            items = items,
            inaccessible = inaccessible
        )

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = when {
                items.isNotEmpty() && inaccessible.isEmpty() -> DiscoveryStatus.FOUND
                items.isNotEmpty() -> DiscoveryStatus.PARTIAL
                inaccessible.isNotEmpty() -> DiscoveryStatus.INACCESSIBLE
                else -> DiscoveryStatus.NOT_FOUND
            },
            accessLevelUsed = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL,
            summary = "Vendor/ODM VINTF, init & permissions scan (${items.size} items).",
            items = items.take(100),
            inaccessibleReasons = inaccessible,
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }
}

class DisplayProbe : FodProbe {
    override val probeId: String = "probe_display"
    override val domain: ProbeDomain = ProbeDomain.DISPLAY

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val items = mutableListOf<ProbeFindingItem>()
        val inaccessible = mutableListOf<String>()

        scanBoundedPaths(
            context = context,
            roots = listOf(
                "/sys/class/backlight",
                "/sys/class/drm",
                "/sys/class/display",
                "/sys/devices/platform"
            ),
            maxDepth = 3,
            keywords = DISPLAY_FOD_KEYWORDS,
            keyPrefix = "display.sysfs",
            items = items,
            inaccessible = inaccessible
        )

        // Read discovered sysfs values up to 15 candidate nodes (non-destructive reads)
        val discoveredSysfs = items.filter { it.location.startsWith("/sys/") }.take(15)
        for (node in discoveredSysfs) {
            val safe = SafeSystemPath.parse(node.location) ?: continue
            val read = context.shellExecutor.execute(
                ShellCommandSpec.ReadSystemFile(safe),
                useRoot = context.allowRoot,
                timeoutMs = 1_500L,
                maxOutputBytes = 2048
            )
            if (read.exitCode == 0 && read.stdout.isNotBlank()) {
                items += ProbeFindingItem(
                    key = "display.value.${node.location.substringAfterLast('/')}",
                    value = read.stdout.trim().take(120),
                    location = node.location,
                    discoveryStatus = DiscoveryStatus.FOUND,
                    epistemicLevel = EpistemicLevel.PROVED,
                    accessLevel = if (read.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                )
            } else if (read.denied) {
                inaccessible += "${node.location} read denied"
            }
        }

        val sfDump = context.shellExecutor.execute(
            ShellCommandSpec.Dumpsys(AllowedDumpsysService.SURFACE_FLINGER),
            useRoot = context.allowRoot
        )
        if (sfDump.exitCode == 0 && sfDump.stdout.isNotBlank()) {
            sfDump.stdout.lineSequence()
                .filter { line ->
                    line.contains("hbm", true) || line.contains("hdr", true) ||
                        line.contains("udfps", true) || line.contains("fod", true) ||
                        line.contains("dim", true) || line.contains("brightness", true) ||
                        line.contains("color mode", true)
                }
                .take(25)
                .forEachIndexed { idx, line ->
                    items += ProbeFindingItem(
                        key = "surfaceflinger.signal.$idx",
                        value = line.trim().take(240),
                        location = "dumpsys SurfaceFlinger",
                        discoveryStatus = DiscoveryStatus.FOUND,
                        epistemicLevel = EpistemicLevel.PROVED,
                        accessLevel = if (sfDump.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                    )
                }
        } else if (sfDump.denied) {
            inaccessible += "dumpsys SurfaceFlinger denied"
        }

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = when {
                items.isNotEmpty() && inaccessible.isEmpty() -> DiscoveryStatus.FOUND
                items.isNotEmpty() -> DiscoveryStatus.PARTIAL
                inaccessible.isNotEmpty() -> DiscoveryStatus.INACCESSIBLE
                else -> DiscoveryStatus.NOT_FOUND
            },
            accessLevelUsed = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL,
            summary = "Display / HBM / Backlight / DRM discovery (${items.size} items).",
            items = items.take(120),
            inaccessibleReasons = inaccessible,
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }
}

class KernelProbe : FodProbe {
    override val probeId: String = "probe_kernel"
    override val domain: ProbeDomain = ProbeDomain.KERNEL

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val items = mutableListOf<ProbeFindingItem>()
        val inaccessible = mutableListOf<String>()

        scanBoundedPaths(
            context = context,
            roots = listOf(
                "/sys/class",
                "/sys/devices/virtual",
                "/sys/bus/platform/devices",
                "/dev"
            ),
            maxDepth = 2,
            keywords = FOD_HAL_KEYWORDS,
            keyPrefix = "kernel.node",
            items = items,
            inaccessible = inaccessible
        )

        val modulesPath = SafeSystemPath.parse("/proc/modules")
        if (modulesPath != null) {
            val modRes = context.shellExecutor.execute(
                ShellCommandSpec.ReadSystemFile(modulesPath),
                useRoot = context.allowRoot
            )
            if (modRes.exitCode == 0 && modRes.stdout.isNotBlank()) {
                modRes.stdout.lineSequence()
                    .filter { line -> (FOD_HAL_KEYWORDS + TOUCH_KERNEL_KEYWORDS).any { line.contains(it, true) } }
                    .take(30)
                    .forEachIndexed { idx, line ->
                        items += ProbeFindingItem(
                            key = "kernel.module.$idx",
                            value = line.trim().take(180),
                            location = "/proc/modules",
                            discoveryStatus = DiscoveryStatus.FOUND,
                            epistemicLevel = EpistemicLevel.PROVED,
                            accessLevel = if (modRes.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                        )
                    }
            } else if (modRes.denied) {
                inaccessible += "/proc/modules denied"
            }
        }

        if (context.allowRoot) {
            val dmesg = context.shellExecutor.execute(ShellCommandSpec.DmesgTail(300), useRoot = true)
            if (dmesg.exitCode == 0 && dmesg.stdout.isNotBlank()) {
                dmesg.stdout.lineSequence()
                    .filter { line -> FOD_HAL_KEYWORDS.any { line.contains(it, true) } }
                    .take(30)
                    .forEachIndexed { idx, line ->
                        items += ProbeFindingItem(
                            key = "kernel.dmesg.$idx",
                            value = line.trim().take(240),
                            location = "dmesg",
                            discoveryStatus = DiscoveryStatus.FOUND,
                            epistemicLevel = EpistemicLevel.PROVED,
                            accessLevel = AccessLevel.ROOT_SU
                        )
                    }
            } else if (dmesg.denied) {
                inaccessible += "dmesg denied"
            }
        } else {
            inaccessible += "dmesg kernel ring buffer requires Root."
        }

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = when {
                items.isNotEmpty() && inaccessible.isEmpty() -> DiscoveryStatus.FOUND
                items.isNotEmpty() -> DiscoveryStatus.PARTIAL
                inaccessible.isNotEmpty() -> DiscoveryStatus.INACCESSIBLE
                else -> DiscoveryStatus.NOT_FOUND
            },
            accessLevelUsed = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL,
            summary = "Kernel drivers, /dev nodes & modules scan (${items.size} items).",
            items = items.take(120),
            inaccessibleReasons = inaccessible,
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }
}

class TouchProbe : FodProbe {
    override val probeId: String = "probe_touch"
    override val domain: ProbeDomain = ProbeDomain.TOUCH

    override suspend fun run(context: ProbeContext): ProbeResult {
        val start = System.currentTimeMillis()
        val items = mutableListOf<ProbeFindingItem>()
        val inaccessible = mutableListOf<String>()

        val inputDevPath = SafeSystemPath.parse("/proc/bus/input/devices")
        if (inputDevPath != null) {
            val res = context.shellExecutor.execute(
                ShellCommandSpec.ReadSystemFile(inputDevPath),
                useRoot = context.allowRoot
            )
            if (res.exitCode == 0 && res.stdout.isNotBlank()) {
                res.stdout.split("\n\n")
                    .filter { block -> TOUCH_KERNEL_KEYWORDS.any { block.contains(it, ignoreCase = true) } }
                    .take(10)
                    .forEachIndexed { idx, block ->
                        items += ProbeFindingItem(
                            key = "touch.input_device.$idx",
                            value = block.lineSequence().take(4).joinToString(" | ").take(240),
                            location = "/proc/bus/input/devices",
                            discoveryStatus = DiscoveryStatus.FOUND,
                            epistemicLevel = EpistemicLevel.PROVED,
                            accessLevel = if (res.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                        )
                    }
            } else if (res.denied) {
                inaccessible += "/proc/bus/input/devices denied"
            }
        }

        scanBoundedPaths(
            context = context,
            roots = listOf("/sys/class/touch", "/sys/devices/virtual/touch", "/sys/devices/platform"),
            maxDepth = 3,
            keywords = TOUCH_KERNEL_KEYWORDS,
            keyPrefix = "touch.sysfs",
            items = items,
            inaccessible = inaccessible
        )

        val inputDump = context.shellExecutor.execute(
            ShellCommandSpec.Dumpsys(AllowedDumpsysService.INPUT),
            useRoot = context.allowRoot
        )
        if (inputDump.exitCode == 0 && inputDump.stdout.isNotBlank()) {
            inputDump.stdout.lineSequence()
                .filter { line ->
                    line.contains("Touch", true) || line.contains("udfps", true) ||
                        line.contains("fod", true) || line.contains("Device ", true)
                }
                .take(25)
                .forEachIndexed { idx, line ->
                    items += ProbeFindingItem(
                        key = "touch.dumpsys_input.$idx",
                        value = line.trim().take(240),
                        location = "dumpsys input",
                        discoveryStatus = DiscoveryStatus.FOUND,
                        epistemicLevel = EpistemicLevel.PROVED,
                        accessLevel = if (inputDump.usedRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL
                    )
                }
        } else if (inputDump.denied) {
            inaccessible += "dumpsys input denied"
        }

        return ProbeResult(
            probeId = probeId,
            domain = domain,
            status = when {
                items.isNotEmpty() && inaccessible.isEmpty() -> DiscoveryStatus.FOUND
                items.isNotEmpty() -> DiscoveryStatus.PARTIAL
                inaccessible.isNotEmpty() -> DiscoveryStatus.INACCESSIBLE
                else -> DiscoveryStatus.NOT_FOUND
            },
            accessLevelUsed = if (context.allowRoot) AccessLevel.ROOT_SU else AccessLevel.UNPRIVILEGED_SHELL,
            summary = "Touch controller & FOD touch node discovery (${items.size} items).",
            items = items.take(100),
            inaccessibleReasons = inaccessible,
            durationMs = System.currentTimeMillis() - start,
            civilTimestampMs = System.currentTimeMillis()
        )
    }
}
