package com.example.fodtracer.system.selinux

import com.example.fodtracer.domain.interfaces.SafeSystemPath
import com.example.fodtracer.domain.interfaces.ShellCommandSpec
import com.example.fodtracer.domain.interfaces.ShellExecutor
import com.example.fodtracer.domain.models.SeLinuxMode
import java.io.File

data class SeLinuxInspectionResult(
    val mode: SeLinuxMode,
    val context: String?,
    val avcDenials: List<String>,
    val accessLimitedNote: String?
)

/**
 * Strictly read-only SELinux inspector. Never disables SELinux or alters policies.
 */
class SeLinuxInspector(
    private val shellExecutor: ShellExecutor
) {
    suspend fun inspect(useRoot: Boolean): SeLinuxInspectionResult {
        var mode = readEnforceFileDirect()
        if (mode == SeLinuxMode.UNKNOWN) {
            val enforceRes = shellExecutor.execute(ShellCommandSpec.GetEnforce, useRoot = false)
            if (enforceRes.exitCode == 0) {
                mode = parseMode(enforceRes.stdout)
            } else if (useRoot) {
                val rootEnforce = shellExecutor.execute(ShellCommandSpec.GetEnforce, useRoot = true)
                if (rootEnforce.exitCode == 0) {
                    mode = parseMode(rootEnforce.stdout)
                }
            }
        }

        val idRes = shellExecutor.execute(ShellCommandSpec.IdCommand, useRoot = useRoot)
        val context = Regex("context=([^\\s]+)").find(idRes.stdout)?.groupValues?.getOrNull(1)

        val avcDenials = mutableListOf<String>()
        var note: String? = null

        val logcatRes = shellExecutor.execute(
            ShellCommandSpec.LogcatSnapshot(listOf("main", "system", "events"), lines = 300),
            useRoot = useRoot
        )
        if (logcatRes.exitCode == 0) {
            avcDenials += extractRelevantAvc(logcatRes.stdout)
        } else if (logcatRes.denied) {
            note = "Logcat inaccessible without elevated privileges."
        }

        if (useRoot) {
            val dmesgRes = shellExecutor.execute(ShellCommandSpec.DmesgTail(250), useRoot = true)
            if (dmesgRes.exitCode == 0) {
                avcDenials += extractRelevantAvc(dmesgRes.stdout)
            } else if (dmesgRes.denied) {
                note = "dmesg denied even under su context."
            }
        } else if (note == null) {
            note = "Kernel dmesg AVC denials require Root verification."
        }

        return SeLinuxInspectionResult(
            mode = mode,
            context = context,
            avcDenials = avcDenials.distinct().take(40),
            accessLimitedNote = note
        )
    }

    private fun readEnforceFileDirect(): SeLinuxMode {
        val sysEnforce = File("/sys/fs/selinux/enforce")
        return runCatching {
            if (!sysEnforce.canRead()) return SeLinuxMode.UNKNOWN
            when (sysEnforce.readText().trim()) {
                "1" -> SeLinuxMode.ENFORCING
                "0" -> SeLinuxMode.PERMISSIVE
                else -> SeLinuxMode.UNKNOWN
            }
        }.getOrDefault(SeLinuxMode.UNKNOWN)
    }

    private fun parseMode(raw: String): SeLinuxMode {
        val lower = raw.trim().lowercase()
        return when {
            lower.contains("enforcing") || lower == "1" -> SeLinuxMode.ENFORCING
            lower.contains("permissive") || lower == "0" -> SeLinuxMode.PERMISSIVE
            lower.contains("disabled") -> SeLinuxMode.DISABLED
            else -> SeLinuxMode.UNKNOWN
        }
    }

    private fun extractRelevantAvc(text: String): List<String> {
        val keywords = listOf(
            "fingerprint", "biometric", "udfps", "fod", "goodix", "fpc", "silead",
            "focaltech", "egis", "hbm", "lhbm", "dimlayer", "touch", "display", "sysfs"
        )
        return text.lineSequence()
            .filter { line ->
                line.contains("avc:") && line.contains("denied") &&
                    keywords.any { kw -> line.contains(kw, ignoreCase = true) }
            }
            .map { it.trim().take(320) }
            .toList()
    }
}
