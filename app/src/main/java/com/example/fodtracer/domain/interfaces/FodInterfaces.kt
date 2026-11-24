package com.example.fodtracer.domain.interfaces

import android.net.Uri
import com.example.fodtracer.domain.models.*
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow

data class ShellExecutionResult(
    val exitCode: Int,
    val stdout: String,
    val stderr: String,
    val truncated: Boolean,
    val timedOut: Boolean,
    val denied: Boolean,
    val usedRoot: Boolean,
    val durationMs: Long,
    val commandDisplay: String
)

data class ShellLogEntry(
    val civilTimestampMs: Long,
    val commandDisplay: String,
    val usedRoot: Boolean,
    val exitCode: Int,
    val timedOut: Boolean,
    val denied: Boolean,
    val outputBytes: Int
)

/**
 * Controlled command specifications. No arbitrary user string is ever concatenated into a shell.
 */
sealed interface ShellCommandSpec {
    val displayName: String

    data object IdCommand : ShellCommandSpec {
        override val displayName: String = "id"
    }

    data object GetEnforce : ShellCommandSpec {
        override val displayName: String = "getenforce"
    }

    data object GetPropAll : ShellCommandSpec {
        override val displayName: String = "getprop"
    }

    data object ServiceList : ShellCommandSpec {
        override val displayName: String = "service list"
    }

    data class Dumpsys(val serviceName: AllowedDumpsysService) : ShellCommandSpec {
        override val displayName: String = "dumpsys ${serviceName.cliName}"
    }

    data object LshalList : ShellCommandSpec {
        override val displayName: String = "lshal"
    }

    data class CmdOverlayList(val userId: Int = 0) : ShellCommandSpec {
        override val displayName: String = "cmd overlay list"
    }

    data class ReadSystemFile(val path: SafeSystemPath) : ShellCommandSpec {
        override val displayName: String = "cat ${path.value}"
    }

    data class ReadSystemHead(val path: SafeSystemPath, val lines: Int = 220) : ShellCommandSpec {
        override val displayName: String = "head -n $lines ${path.value}"
    }

    data class ListSystemDir(val path: SafeSystemPath, val maxDepth: Int = 2) : ShellCommandSpec {
        override val displayName: String = "find_bounded ${path.value}"
    }

    data class LogcatSnapshot(val buffers: List<String>, val lines: Int = 400) : ShellCommandSpec {
        override val displayName: String = "logcat -d -t $lines"
    }

    data class DmesgTail(val lines: Int = 200) : ShellCommandSpec {
        override val displayName: String = "dmesg"
    }

    data class ReadSystemBinaryBase64(
        val path: SafeSystemPath,
        val offsetBytes: Long = 0L,
        val maxBytes: Int = 1_572_864
    ) : ShellCommandSpec {
        override val displayName: String = "dd_b64 ${path.value}"
    }

    data class ListProcesses(val dummy: Boolean = true) : ShellCommandSpec {
        override val displayName: String = "ps -A"
    }

    data class InspectProcPid(
        val pid: Int,
        val target: AllowedProcTarget
    ) : ShellCommandSpec {
        override val displayName: String = "proc/$pid/${target.cliName}"
    }
}

enum class AllowedProcTarget(val cliName: String) {
    FD("fd"),
    MAPS("maps"),
    CMDLINE("cmdline"),
    STATUS("status"),
    STACK("stack"),
    WCHAN("wchan"),
    SYSCALL("syscall")
}

enum class AllowedDumpsysService(val cliName: String) {
    FINGERPRINT("fingerprint"),
    BIOMETRIC("biometric"),
    SURFACE_FLINGER("SurfaceFlinger"),
    DISPLAY("display"),
    POWER("power"),
    INPUT("input"),
    OVERLAY("overlay")
}

/**
 * Strictly validated read-only system path confined to approved diagnostic roots.
 */
@JvmInline
value class SafeSystemPath private constructor(val value: String) {
    companion object {
        private val ALLOWED_ROOTS = listOf(
            "/sys/",
            "/proc/",
            "/dev/",
            "/vendor/",
            "/odm/",
            "/system/",
            "/system_ext/",
            "/product/",
            "/apex/"
        )

        private val SAFE_CHARS = Regex("^[a-zA-Z0-9_./:@+-]+$")

        fun parse(raw: String): SafeSystemPath? {
            val trimmed = raw.trim()
            if (trimmed.isEmpty() || trimmed.length > 260) return null
            if (trimmed.contains("..") || !SAFE_CHARS.matches(trimmed)) return null
            if (ALLOWED_ROOTS.none { trimmed.startsWith(it) || trimmed == it.removeSuffix("/") }) {
                return null
            }
            return SafeSystemPath(trimmed)
        }
    }
}

interface ShellExecutor {
    val recentLogs: StateFlow<List<ShellLogEntry>>
    suspend fun execute(
        spec: ShellCommandSpec,
        useRoot: Boolean = false,
        timeoutMs: Long = 3_500L,
        maxOutputBytes: Int = 196_608
    ): ShellExecutionResult
}

data class PrivilegeSnapshot(
    val suBinaryFound: Boolean,
    val suBinaryPath: String?,
    val rootState: RootState,
    val rootProviderHint: String?,
    val rootUidInfo: String?,
    val seLinuxMode: SeLinuxMode,
    val seLinuxContext: String?,
    val manageExternalStorageGranted: Boolean,
    val postNotificationsGranted: Boolean,
    val publicFodDirPath: String,
    val publicFodDirWritable: Boolean,
    val rootDiagnosticNote: String? = null
)

interface PrivilegeManager {
    val snapshot: StateFlow<PrivilegeSnapshot>
    suspend fun refreshStatus(): PrivilegeSnapshot
    suspend fun requestAndVerifyRoot(): PrivilegeSnapshot
}

data class ProbeContext(
    val shellExecutor: ShellExecutor,
    val allowRoot: Boolean,
    val seLinuxMode: SeLinuxMode
)

interface FodProbe {
    val probeId: String
    val domain: ProbeDomain
    suspend fun run(context: ProbeContext): ProbeResult
}

interface DiagnosticRepository {
    val sessions: Flow<List<DiagnosticSession>>
    val activeSession: StateFlow<DiagnosticSession?>
    suspend fun saveSession(session: DiagnosticSession)
    suspend fun getSessionById(sessionId: String): DiagnosticSession?
    suspend fun deleteSession(sessionId: String)
    suspend fun setActiveSession(sessionId: String?)
    suspend fun saveComparison(report: ComparisonReport)
    val comparisons: Flow<List<ComparisonReport>>
    suspend fun getComparisonById(comparisonId: String): ComparisonReport?
}

interface ArchiveRepository {
    suspend fun exportDiagnosticZip(
        session: DiagnosticSession,
        anonymize: Boolean,
        destinationUri: Uri? = null
    ): Result<String>

    suspend fun exportDiagnosticMarkdown(
        session: DiagnosticSession,
        anonymize: Boolean,
        destinationUri: Uri? = null
    ): Result<String>

    suspend fun importDiagnosticZip(sourceUri: Uri): Result<DiagnosticSession>
    suspend fun listPublicArchives(): List<String>
    suspend fun importPublicArchiveByName(fileName: String): Result<DiagnosticSession>
}

interface PreferencesRepository {
    val themePreference: Flow<ThemePreference>
    val languagePreference: Flow<LanguagePreference>
    val aiEnabled: Flow<Boolean>
    val anonymizeByDefault: Flow<Boolean>
    val preferRootProbes: Flow<Boolean>
    suspend fun setThemePreference(pref: ThemePreference)
    suspend fun setLanguagePreference(pref: LanguagePreference)
    suspend fun setAiEnabled(enabled: Boolean)
    suspend fun setAnonymizeByDefault(enabled: Boolean)
    suspend fun setPreferRootProbes(enabled: Boolean)
}

interface AiAdvisorService {
    fun isFirebaseConfigured(): Boolean
    suspend fun analyzeDiagnostic(session: DiagnosticSession): Result<AIAnalysis>
    suspend fun analyzeComparison(report: ComparisonReport): Result<AIAnalysis>
}
