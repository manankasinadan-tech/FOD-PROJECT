package com.example.fodtracer.system.root

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Environment
import androidx.core.content.ContextCompat
import com.example.fodtracer.domain.interfaces.*
import com.example.fodtracer.domain.models.RootState
import com.example.fodtracer.domain.models.SeLinuxMode
import com.example.fodtracer.system.selinux.SeLinuxInspector
import com.example.fodtracer.system.shell.SafeShellExecutor
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.withContext
import java.io.File

class AndroidPrivilegeManager(
    private val context: Context,
    private val shellExecutor: ShellExecutor,
    private val seLinuxInspector: SeLinuxInspector
) : PrivilegeManager {

    private val privPrefs by lazy {
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
    }

    private val _snapshot = MutableStateFlow(
        PrivilegeSnapshot(
            suBinaryFound = false,
            suBinaryPath = null,
            rootState = RootState.NOT_CHECKED,
            rootProviderHint = null,
            rootUidInfo = null,
            seLinuxMode = SeLinuxMode.UNKNOWN,
            seLinuxContext = null,
            manageExternalStorageGranted = false,
            postNotificationsGranted = false,
            publicFodDirPath = PUBLIC_FOD_DIR_PATH,
            publicFodDirWritable = false,
            rootDiagnosticNote = null
        )
    )
    override val snapshot: StateFlow<PrivilegeSnapshot> = _snapshot.asStateFlow()

    override suspend fun refreshStatus(): PrivilegeSnapshot = withContext(Dispatchers.IO) {
        val suPath = SafeShellExecutor.findDefaultSuBinary()
        val providerHint = detectRootProviderHint()
        val previouslyVerified = privPrefs.getBoolean(KEY_ROOT_VERIFIED, false)

        // If user already verified root in this app earlier (or manager already granted su silently),
        // verify silently on refresh so Root stays active across app restarts.
        if (previouslyVerified && _snapshot.value.rootState != RootState.GRANTED_VERIFIED) {
            val silentCheck = shellExecutor.execute(ShellCommandSpec.IdCommand, useRoot = true, timeoutMs = 2_500L)
            if (silentCheck.exitCode == 0 && silentCheck.stdout.contains("uid=0")) {
                return@withContext finalizeVerifiedRoot(suPath ?: "su", providerHint, silentCheck)
            }
        }

        val seLinuxInfo = seLinuxInspector.inspect(useRoot = _snapshot.value.rootState == RootState.GRANTED_VERIFIED)
        val storageGranted = isManageExternalStorageGranted()
        val notifGranted = isPostNotificationsGranted()
        val publicWritable = checkPublicDirWritable(storageGranted)

        val currentRootState = _snapshot.value.rootState
        val resolvedRootState = when {
            currentRootState == RootState.GRANTED_VERIFIED -> RootState.GRANTED_VERIFIED
            currentRootState == RootState.DENIED -> RootState.DENIED
            suPath != null || providerHint != null -> RootState.AVAILABLE_NOT_GRANTED
            else -> RootState.NOT_AVAILABLE
        }

        val updated = PrivilegeSnapshot(
            suBinaryFound = suPath != null,
            suBinaryPath = suPath,
            rootState = resolvedRootState,
            rootProviderHint = providerHint,
            rootUidInfo = _snapshot.value.rootUidInfo,
            seLinuxMode = seLinuxInfo.mode,
            seLinuxContext = seLinuxInfo.context,
            manageExternalStorageGranted = storageGranted,
            postNotificationsGranted = notifGranted,
            publicFodDirPath = PUBLIC_FOD_DIR_PATH,
            publicFodDirWritable = publicWritable,
            rootDiagnosticNote = _snapshot.value.rootDiagnosticNote
        )
        _snapshot.value = updated
        updated
    }

    override suspend fun requestAndVerifyRoot(): PrivilegeSnapshot = withContext(Dispatchers.IO) {
        val discoveredSu = SafeShellExecutor.findDefaultSuBinary()
        val providerHint = detectRootProviderHint()

        // Always attempt real su execution even if File.exists() returned false (KernelSU / APatch / Zygisk namespace hiding)
        val attempts = buildList {
            if (discoveredSu != null) add(discoveredSu)
            add("su")
            SafeShellExecutor.SU_CANDIDATE_PATHS.forEach { path ->
                if (path != discoveredSu) add(path)
            }
        }.distinct()

        var verifiedPath: String? = null
        var lastIdResult: ShellExecutionResult? = null

        val safeExec = shellExecutor as? SafeShellExecutor
        for ((index, candidate) in attempts.withIndex()) {
            val timeout = if (index <= 1) 15_000L else 2_500L
            val idRes = if (safeExec != null && candidate != discoveredSu && candidate != "su") {
                safeExec.executeWithExplicitSu(ShellCommandSpec.IdCommand, candidate, timeoutMs = timeout)
            } else {
                shellExecutor.execute(ShellCommandSpec.IdCommand, useRoot = true, timeoutMs = timeout)
            }
            lastIdResult = idRes
            if (idRes.exitCode == 0 && idRes.stdout.contains("uid=0")) {
                verifiedPath = candidate
                break
            }
            // If user explicitly denied the prompt (not a missing-binary ENOENT error), stop retrying other paths
            val errLower = idRes.stderr.lowercase()
            if (idRes.denied && !errLower.contains("no such file") && !errLower.contains("cannot run program")) {
                break
            }
        }

        if (verifiedPath != null && lastIdResult != null) {
            // Confirm real kernel read capability
            val procVersionPath = SafeSystemPath.parse("/proc/version")
            val readVerify = if (procVersionPath != null) {
                if (safeExec != null && verifiedPath != discoveredSu && verifiedPath != "su") {
                    safeExec.executeWithExplicitSu(ShellCommandSpec.ReadSystemFile(procVersionPath), verifiedPath, timeoutMs = 4_000L)
                } else {
                    shellExecutor.execute(ShellCommandSpec.ReadSystemFile(procVersionPath), useRoot = true, timeoutMs = 4_000L)
                }
            } else null

            if (readVerify == null || readVerify.exitCode == 0) {
                return@withContext finalizeVerifiedRoot(verifiedPath, providerHint, lastIdResult)
            }
        }

        privPrefs.edit().putBoolean(KEY_ROOT_VERIFIED, false).apply()

        val errReason = lastIdResult?.stderr?.ifBlank { "exit=${lastIdResult.exitCode}" } ?: "su execution unavailable"
        val note = when {
            providerHint?.contains("KernelSU", ignoreCase = true) == true ->
                "KernelSU detected: open KernelSU Manager -> Superuser -> enable FodTracer explicitly ($errReason)."
            providerHint?.contains("APatch", ignoreCase = true) == true ->
                "APatch detected: authorize FodTracer in APatch Superuser list ($errReason)."
            providerHint?.contains("Magisk", ignoreCase = true) == true ->
                "Magisk detected: ensure FodTracer is granted Superuser and NOT in DenyList ($errReason)."
            else -> "su attempt failed: $errReason"
        }

        val finalRootState = if (lastIdResult?.denied == true || providerHint != null || discoveredSu != null) {
            RootState.DENIED
        } else {
            RootState.NOT_AVAILABLE
        }

        val seLinuxInfo = seLinuxInspector.inspect(useRoot = false)
        val storageGranted = isManageExternalStorageGranted()
        val updated = PrivilegeSnapshot(
            suBinaryFound = discoveredSu != null,
            suBinaryPath = discoveredSu,
            rootState = finalRootState,
            rootProviderHint = providerHint,
            rootUidInfo = null,
            seLinuxMode = seLinuxInfo.mode,
            seLinuxContext = seLinuxInfo.context,
            manageExternalStorageGranted = storageGranted,
            postNotificationsGranted = isPostNotificationsGranted(),
            publicFodDirPath = PUBLIC_FOD_DIR_PATH,
            publicFodDirWritable = checkPublicDirWritable(storageGranted),
            rootDiagnosticNote = note
        )
        _snapshot.value = updated
        updated
    }

    private suspend fun finalizeVerifiedRoot(
        verifiedSuPath: String,
        initialProviderHint: String?,
        idResult: ShellExecutionResult
    ): PrivilegeSnapshot {
        privPrefs.edit().putBoolean(KEY_ROOT_VERIFIED, true).apply()
        val seLinuxInfo = seLinuxInspector.inspect(useRoot = true)
        val storageGranted = isManageExternalStorageGranted()
        val resolvedProvider = initialProviderHint ?: when {
            verifiedSuPath.contains("ksu", true) -> "KernelSU"
            verifiedSuPath.contains("/ap/", true) -> "APatch"
            verifiedSuPath.contains("magisk", true) -> "Magisk"
            idResult.stdout.contains("magisk", true) -> "Magisk"
            else -> "Root (su)"
        }

        val updated = PrivilegeSnapshot(
            suBinaryFound = true,
            suBinaryPath = verifiedSuPath,
            rootState = RootState.GRANTED_VERIFIED,
            rootProviderHint = resolvedProvider,
            rootUidInfo = idResult.stdout.trim().lineSequence().firstOrNull(),
            seLinuxMode = seLinuxInfo.mode,
            seLinuxContext = seLinuxInfo.context,
            manageExternalStorageGranted = storageGranted,
            postNotificationsGranted = isPostNotificationsGranted(),
            publicFodDirPath = PUBLIC_FOD_DIR_PATH,
            publicFodDirWritable = checkPublicDirWritable(storageGranted),
            rootDiagnosticNote = "Verified via $verifiedSuPath"
        )
        _snapshot.value = updated
        return updated
    }

    private fun detectRootProviderHint(): String? {
        val pm = context.packageManager
        val knownManagers = mapOf(
            "com.topjohnwu.magisk" to "Magisk",
            "io.github.vvb2060.magisk" to "Magisk Alpha",
            "me.weishu.kernelsu" to "KernelSU",
            "com.rifsxd.ksunext" to "KernelSU Next",
            "me.bmax.apatch" to "APatch"
        )
        for ((pkg, label) in knownManagers) {
            val installed = runCatching {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    pm.getPackageInfo(pkg, PackageManager.PackageInfoFlags.of(0))
                } else {
                    @Suppress("DEPRECATION")
                    pm.getPackageInfo(pkg, 0)
                }
            }.isSuccess
            if (installed) return label
        }
        return when {
            File("/data/adb/ksu").exists() -> "KernelSU"
            File("/data/adb/ap").exists() -> "APatch"
            File("/data/adb/magisk").exists() -> "Magisk"
            else -> null
        }
    }

    private fun isManageExternalStorageGranted(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.WRITE_EXTERNAL_STORAGE
            ) == PackageManager.PERMISSION_GRANTED
        }
    }

    private fun isPostNotificationsGranted(): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            ContextCompat.checkSelfPermission(
                context,
                Manifest.permission.POST_NOTIFICATIONS
            ) == PackageManager.PERMISSION_GRANTED
        } else {
            true
        }
    }

    private fun checkPublicDirWritable(storageGranted: Boolean): Boolean {
        if (!storageGranted) return false
        return runCatching {
            val dir = File(PUBLIC_FOD_DIR_PATH)
            if (!dir.exists()) dir.mkdirs()
            dir.exists() && dir.canWrite()
        }.getOrDefault(false)
    }

    companion object {
        private const val PREFS_NAME = "fodtracer_priv"
        private const val KEY_ROOT_VERIFIED = "root_previously_verified"

        val PUBLIC_FOD_DIR_PATH: String =
            File(Environment.getExternalStorageDirectory(), "FODtracer").absolutePath
    }
}
