package com.example.fodtracer.core.probe

import android.content.Context
import android.os.Build
import com.example.fodtracer.domain.interfaces.*
import com.example.fodtracer.domain.models.*
import com.example.fodtracer.system.biometrics.AndroidBiometricInspector
import com.example.fodtracer.system.selinux.SeLinuxInspector
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOn

data class ProbeExecutionProgress(
    val completedCount: Int,
    val totalCount: Int,
    val currentDomain: ProbeDomain,
    val latestResult: ProbeResult? = null
)

data class ColdDiscoveryOutput(
    val environment: DeviceEnvironment,
    val probeResults: List<ProbeResult>,
    val components: List<DiscoveredComponent>
)

class ProbeEngine(
    private val androidContext: Context,
    private val shellExecutor: ShellExecutor,
    private val privilegeManager: PrivilegeManager
) {
    private val seLinuxInspector = SeLinuxInspector(shellExecutor)

    private val probes: List<FodProbe> = listOf(
        HardwareProbe(androidContext),
        PropertiesProbe(),
        SeLinuxProbe(seLinuxInspector),
        BiometricProbe(androidContext),
        FrameworkProbe(),
        SystemUiProbe(androidContext),
        HalProbe(),
        VendorProbe(),
        DisplayProbe(),
        KernelProbe(),
        TouchProbe(),
        OverlayProbe()
    )

    fun runColdDiagnostic(): Flow<Pair<ProbeExecutionProgress, ColdDiscoveryOutput?>> = flow {
        val priv = privilegeManager.refreshStatus()
        val allowRoot = priv.rootState == RootState.GRANTED_VERIFIED
        val context = ProbeContext(
            shellExecutor = shellExecutor,
            allowRoot = allowRoot,
            seLinuxMode = priv.seLinuxMode
        )

        val results = mutableListOf<ProbeResult>()
        val total = probes.size

        probes.forEachIndexed { index, probe ->
            emit(
                ProbeExecutionProgress(
                    completedCount = index,
                    totalCount = total,
                    currentDomain = probe.domain,
                    latestResult = results.lastOrNull()
                ) to null
            )
            val result = probe.run(context)
            results += result
        }

        val propsMap = extractPropertiesMap(results)
        val environment = buildDeviceEnvironment(priv, propsMap)
        val components = synthesizeComponents(results)

        val finalOutput = ColdDiscoveryOutput(
            environment = environment,
            probeResults = results,
            components = components
        )
        emit(
            ProbeExecutionProgress(
                completedCount = total,
                totalCount = total,
                currentDomain = probes.last().domain,
                latestResult = results.lastOrNull()
            ) to finalOutput
        )
    }.flowOn(Dispatchers.IO)

    private fun extractPropertiesMap(results: List<ProbeResult>): Map<String, String> {
        val propResult = results.firstOrNull { it.domain == ProbeDomain.PROPERTIES } ?: return emptyMap()
        return propResult.items.associate { it.key to it.value }
    }

    private fun buildDeviceEnvironment(
        priv: PrivilegeSnapshot,
        props: Map<String, String>
    ): DeviceEnvironment {
        val bioSnapshot = AndroidBiometricInspector(androidContext).inspectBiometricState()
        val trebleEnabled = props["ro.treble.enabled"]?.equals("true", ignoreCase = true) == true
        val vndk = props["ro.vndk.version"] ?: props["ro.board.api_level"] ?: "unknown"
        val fingerprint = Build.FINGERPRINT
        val display = Build.DISPLAY

        val (romType, romEvidence) = classifyRomType(fingerprint, display, props)

        return DeviceEnvironment(
            model = Build.MODEL,
            manufacturer = Build.MANUFACTURER,
            brand = Build.BRAND,
            device = Build.DEVICE,
            hardware = Build.HARDWARE,
            board = Build.BOARD,
            socManufacturer = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) Build.SOC_MANUFACTURER else (props["ro.soc.manufacturer"] ?: "unknown"),
            socModel = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) Build.SOC_MODEL else (props["ro.soc.model"] ?: Build.HARDWARE),
            androidVersion = Build.VERSION.RELEASE ?: "unknown",
            sdkInt = Build.VERSION.SDK_INT,
            securityPatch = Build.VERSION.SECURITY_PATCH,
            buildFingerprint = fingerprint,
            buildDisplay = display,
            isTrebleEnabled = trebleEnabled,
            vndkVersion = vndk,
            detectedRomType = romType,
            romTypeEvidence = romEvidence,
            rootState = priv.rootState,
            rootProviderHint = priv.rootProviderHint,
            seLinuxMode = priv.seLinuxMode,
            seLinuxContext = priv.seLinuxContext,
            hasFingerprintFeature = bioSnapshot.hasFingerprintFeature,
            biometricHardwareStatus = bioSnapshot.statusCodeLabel,
            civilTimestampMs = System.currentTimeMillis()
        )
    }

    private fun classifyRomType(
        fingerprint: String,
        display: String,
        props: Map<String, String>
    ): Pair<RomType, String> {
        val allKeys = props.keys.joinToString(" ").lowercase()
        val combined = "$fingerprint $display ${props.entries.joinToString(" ") { "${it.key}=${it.value}" }}".lowercase()
        return when {
            combined.contains("treble_arm64") || combined.contains("aosp_arm64") ||
                allKeys.contains("sys.phh.") || allKeys.contains("persist.sys.phh.") ||
                combined.contains("gsi_") || combined.contains("_gsi") -> {
                RomType.GSI to "Detected Treble/GSI build markers (gsi/phh/aosp_arm64)."
            }
            combined.contains("lineage") || combined.contains("crdroid") ||
                combined.contains("evolution") || combined.contains("pixelos") ||
                combined.contains("derpfest") || combined.contains("rising") ||
                combined.contains("arrow") || combined.contains("userdebug") -> {
                RomType.CUSTOM_ROM to "Detected Custom ROM build properties/markers."
            }
            combined.contains("release-keys") -> {
                RomType.STOCK to "Detected release-keys without GSI/Custom ROM markers."
            }
            else -> RomType.UNKNOWN to "Insufficient markers to definitively classify ROM type."
        }
    }

    private fun synthesizeComponents(results: List<ProbeResult>): List<DiscoveredComponent> {
        val components = mutableListOf<DiscoveredComponent>()
        var compIdx = 0

        fun nextId(prefix: String): String {
            compIdx += 1
            return "COMP-${prefix}-${compIdx.toString().padStart(3, '0')}"
        }

        results.forEach { result ->
            when (result.domain) {
                ProbeDomain.SYSTEMUI -> {
                    val sysUiPkg = result.items.firstOrNull { it.key.contains("com.android.systemui") }
                    if (sysUiPkg != null) {
                        components += DiscoveredComponent(
                            id = nextId("SYSUI"),
                            name = "SystemUI & UdfpsController Host",
                            domain = ProbeDomain.SYSTEMUI,
                            role = ComponentRole.APPLICATION_SYSTEMUI,
                            partition = inferPartition(sysUiPkg.location),
                            location = sysUiPkg.location,
                            interfaces = result.items.filter { it.key.contains("log_signal") }.map { it.value.take(80) }.take(5),
                            discoveryStatus = DiscoveryStatus.FOUND,
                            epistemicLevel = EpistemicLevel.PROVED
                        )
                    }
                }
                ProbeDomain.BIOMETRIC -> {
                    components += DiscoveredComponent(
                        id = nextId("BIO"),
                        name = "BiometricService / FingerprintService",
                        domain = ProbeDomain.BIOMETRIC,
                        role = ComponentRole.BIOMETRIC_SERVICE,
                        partition = PartitionOrigin.SYSTEM,
                        location = "Binder: biometric / fingerprint",
                        interfaces = result.items.filter { it.discoveryStatus == DiscoveryStatus.FOUND }.map { it.value.take(90) }.take(6),
                        discoveryStatus = result.status,
                        epistemicLevel = if (result.status == DiscoveryStatus.FOUND) EpistemicLevel.PROVED else EpistemicLevel.CORRELATED
                    )
                }
                ProbeDomain.HAL -> {
                    val halItems = result.items.filter { it.discoveryStatus == DiscoveryStatus.FOUND }
                    if (halItems.isNotEmpty()) {
                        components += DiscoveredComponent(
                            id = nextId("HAL"),
                            name = "Biometric / Fingerprint HAL",
                            domain = ProbeDomain.HAL,
                            role = ComponentRole.BIOMETRIC_HAL,
                            partition = inferPartition(halItems.first().location),
                            location = halItems.first().location,
                            interfaces = halItems.map { it.value }.take(8),
                            discoveryStatus = result.status,
                            epistemicLevel = EpistemicLevel.PROVED
                        )
                    } else {
                        components += DiscoveredComponent(
                            id = nextId("HAL"),
                            name = "Biometric / Fingerprint HAL",
                            domain = ProbeDomain.HAL,
                            role = ComponentRole.BIOMETRIC_HAL,
                            partition = PartitionOrigin.VENDOR,
                            location = "lshal / vendor/odm",
                            discoveryStatus = result.status,
                            epistemicLevel = if (result.status == DiscoveryStatus.INACCESSIBLE) EpistemicLevel.INACCESSIBLE else EpistemicLevel.HYPOTHESIS
                        )
                    }
                }
                ProbeDomain.DISPLAY -> {
                    val dispItems = result.items.filter { it.discoveryStatus == DiscoveryStatus.FOUND }
                    components += DiscoveredComponent(
                        id = nextId("DISP"),
                        name = "Display / HBM / Backlight Subsystem",
                        domain = ProbeDomain.DISPLAY,
                        role = ComponentRole.DISPLAY_HBM,
                        partition = if (dispItems.any { it.location.startsWith("/sys/") }) PartitionOrigin.KERNEL else PartitionOrigin.SYSTEM,
                        location = dispItems.firstOrNull()?.location ?: "/sys/class/backlight / SurfaceFlinger",
                        interfaces = dispItems.map { it.location }.distinct().take(8),
                        discoveryStatus = result.status,
                        epistemicLevel = if (dispItems.isNotEmpty()) EpistemicLevel.PROVED else EpistemicLevel.INACCESSIBLE
                    )
                }
                ProbeDomain.TOUCH -> {
                    val touchItems = result.items.filter { it.discoveryStatus == DiscoveryStatus.FOUND }
                    components += DiscoveredComponent(
                        id = nextId("TOUCH"),
                        name = "Touch Controller & Input Subsystem",
                        domain = ProbeDomain.TOUCH,
                        role = ComponentRole.TOUCH_CONTROLLER,
                        partition = PartitionOrigin.KERNEL,
                        location = touchItems.firstOrNull()?.location ?: "/proc/bus/input/devices",
                        interfaces = touchItems.map { it.location }.distinct().take(6),
                        discoveryStatus = result.status,
                        epistemicLevel = if (touchItems.isNotEmpty()) EpistemicLevel.PROVED else EpistemicLevel.INACCESSIBLE
                    )
                }
                ProbeDomain.KERNEL -> {
                    val kernelItems = result.items.filter { it.discoveryStatus == DiscoveryStatus.FOUND }
                    components += DiscoveredComponent(
                        id = nextId("KERN"),
                        name = "Fingerprint Kernel Driver / Sysfs",
                        domain = ProbeDomain.KERNEL,
                        role = ComponentRole.KERNEL_DRIVER,
                        partition = PartitionOrigin.KERNEL,
                        location = kernelItems.firstOrNull()?.location ?: "/sys /dev",
                        interfaces = kernelItems.map { it.location }.distinct().take(6),
                        discoveryStatus = result.status,
                        epistemicLevel = if (kernelItems.isNotEmpty()) EpistemicLevel.PROVED else EpistemicLevel.INACCESSIBLE
                    )
                }
                ProbeDomain.OVERLAY -> {
                    val ovItems = result.items.filter { it.discoveryStatus == DiscoveryStatus.FOUND }
                    components += DiscoveredComponent(
                        id = nextId("RRO"),
                        name = "Runtime Resource Overlays (RRO)",
                        domain = ProbeDomain.OVERLAY,
                        role = ComponentRole.RESOURCE_OVERLAY,
                        partition = PartitionOrigin.PRODUCT,
                        location = "cmd overlay list",
                        interfaces = ovItems.map { "${it.key}: ${it.value}" }.take(10),
                        discoveryStatus = result.status,
                        epistemicLevel = if (ovItems.isNotEmpty()) EpistemicLevel.PROVED else EpistemicLevel.INACCESSIBLE
                    )
                }
                ProbeDomain.VENDOR -> {
                    val vendorItems = result.items.filter { it.discoveryStatus == DiscoveryStatus.FOUND }
                    if (vendorItems.isNotEmpty()) {
                        components += DiscoveredComponent(
                            id = nextId("VEND"),
                            name = "Vendor / ODM Biometric Artifacts",
                            domain = ProbeDomain.VENDOR,
                            role = ComponentRole.VENDOR_SERVICE,
                            partition = inferPartition(vendorItems.first().location),
                            location = vendorItems.first().location,
                            interfaces = vendorItems.map { it.value }.take(8),
                            discoveryStatus = result.status,
                            epistemicLevel = EpistemicLevel.PROVED
                        )
                    }
                }
                else -> Unit
            }
        }
        return components
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
