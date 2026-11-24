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
            publicFodDirWritable = false
        )
    )
    override val snapshot: StateFlow<PrivilegeSnapshot> = _snapshot.asStateFlow()

    override suspend fun refreshStatus(): PrivilegeSnapshot = withContext(Dispatchers.IO) {
        val suPath = SafeShellExecutor.findDefaultSuBinary()
        val providerHint = detectRootProviderHint()
        val seLinuxInfo = seLinuxInspector.inspect(useRoot = false)
        val storageGranted = isManageExternalStorageGranted()
        val notifGranted = isPostNotificationsGranted()
        val publicWritable = checkPublicDirWritable(storageGranted)

        val currentRootState = _snapshot.value.rootState
        val resolvedRootState = when {
            suPath == null && providerHint == null -> RootState.NOT_AVAILABLE
            currentRootState == RootState.GRANTED_VERIFIED -> RootState.GRANTED_VERIFIED
            currentRootState == RootState.DENIED -> RootState.DENIED
            else -> RootState.AVAILABLE_NOT_GRANTED
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
            publicFodDirWritable = publicWritable
        )
        _snapshot.value = updated
        updated
    }

    override suspend fun requestAndVerifyRoot(): PrivilegeSnapshot = withContext(Dispatchers.IO) {
        val suPath = SafeShellExecutor.findDefaultSuBinary()
        val providerHint = detectRootProviderHint()

        if (suPath == null) {
            val noSuSnapshot = refreshStatus().copy(
                suBinaryFound = false,
                rootState = RootState.NOT_AVAILABLE,
                rootUidInfo = null
            )
            _snapshot.value = noSuSnapshot
            return@withContext noSuSnapshot
        }

        val idResult = shellExecutor.execute(ShellCommandSpec.IdCommand, useRoot = true, timeoutMs = 6_000L)
        val hasUidZero = idResult.exitCode == 0 && idResult.stdout.contains("uid=0")

        // Real read verification on a kernel/proc node in addition to `id`
        val procVersionPath = SafeSystemPath.parse("/proc/version")
        val readVerify = if (hasUidZero && procVersionPath != null) {
            shellExecutor.execute(ShellCommandSpec.ReadSystemFile(procVersionPath), useRoot = true, timeoutMs = 3_000L)
        } else null

        val verified = hasUidZero && (readVerify?.exitCode == 0)
        val rootState = when {
            verified -> RootState.GRANTED_VERIFIED
            idResult.denied || idResult.exitCode != 0 -> RootState.DENIED
            else -> RootState.DENIED
        }

        val seLinuxInfo = seLinuxInspector.inspect(useRoot = verified)
        val storageGranted = isManageExternalStorageGranted()

        val updated = PrivilegeSnapshot(
            suBinaryFound = true,
            suBinaryPath = suPath,
            rootState = rootState,
            rootProviderHint = providerHint,
            rootUidInfo = if (verified) idResult.stdout.trim().lineSequence().firstOrNull() else null,
            seLinuxMode = seLinuxInfo.mode,
            seLinuxContext = seLinuxInfo.context,
            manageExternalStorageGranted = storageGranted,
            postNotificationsGranted = isPostNotificationsGranted(),
            publicFodDirPath = PUBLIC_FOD_DIR_PATH,
            publicFodDirWritable = checkPublicDirWritable(storageGranted)
        )
        _snapshot.value = updated
        updated
    }

    private fun detectRootProviderHint(): String? {
        val pm = context.packageManager
        val knownManagers = mapOf(
            "com.topjohnwu.magisk" to "Magisk",
            "io.github.vvb2060.magisk" to "Magisk Alpha",
            "me.weishu.kernelsu" to "KernelSU",
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
        val PUBLIC_FOD_DIR_PATH: String =
            File(Environment.getExternalStorageDirectory(), "FODtracer").absolutePath
    }
}
