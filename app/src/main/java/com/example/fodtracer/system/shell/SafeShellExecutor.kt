package com.example.fodtracer.system.shell

import com.example.fodtracer.domain.interfaces.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.InputStream
import java.nio.charset.StandardCharsets

class SafeShellExecutor(
    private val suBinaryResolver: () -> String? = ::findDefaultSuBinary
) : ShellExecutor {

    private val _recentLogs = MutableStateFlow<List<ShellLogEntry>>(emptyList())
    override val recentLogs: StateFlow<List<ShellLogEntry>> = _recentLogs.asStateFlow()

    override suspend fun execute(
        spec: ShellCommandSpec,
        useRoot: Boolean,
        timeoutMs: Long,
        maxOutputBytes: Int
    ): ShellExecutionResult = withContext(Dispatchers.IO) {
        val startNanos = System.nanoTime()
        val args = buildArgv(spec)

        if (args.isEmpty()) {
            return@withContext ShellExecutionResult(
                exitCode = -1,
                stdout = "",
                stderr = "Invalid or disallowed command specification.",
                truncated = false,
                timedOut = false,
                denied = true,
                usedRoot = useRoot,
                durationMs = 0L,
                commandDisplay = spec.displayName
            )
        }

        val suPath = if (useRoot) suBinaryResolver() else null
        if (useRoot && suPath == null) {
            return@withContext ShellExecutionResult(
                exitCode = -1,
                stdout = "",
                stderr = "su binary not found.",
                truncated = false,
                timedOut = false,
                denied = true,
                usedRoot = true,
                durationMs = 0L,
                commandDisplay = spec.displayName
            )
        }

        var process: Process? = null
        try {
            val pb = if (useRoot && suPath != null) {
                ProcessBuilder(suPath, "-c", args.joinToString(" "))
            } else {
                ProcessBuilder(args)
            }
            pb.redirectErrorStream(false)
            process = pb.start()

            val activeProcess = process
            val result = withTimeoutOrNull(timeoutMs) {
                coroutineScope {
                    val stdoutJob = async(Dispatchers.IO) {
                        readBoundedStream(activeProcess.inputStream, maxOutputBytes)
                    }
                    val stderrJob = async(Dispatchers.IO) {
                        readBoundedStream(activeProcess.errorStream, maxOutputBytes / 4)
                    }
                    val exitCode = activeProcess.waitFor()
                    val out = stdoutJob.await()
                    val err = stderrJob.await()
                    Triple(exitCode, out, err)
                }
            }

            val elapsedMs = ((System.nanoTime() - startNanos) / 1_000_000L).coerceAtLeast(0L)
            if (result == null) {
                activeProcess.destroyForcibly()
                val timedOutRes = ShellExecutionResult(
                    exitCode = -1,
                    stdout = "",
                    stderr = "Command timed out after ${timeoutMs}ms.",
                    truncated = false,
                    timedOut = true,
                    denied = false,
                    usedRoot = useRoot,
                    durationMs = elapsedMs,
                    commandDisplay = spec.displayName
                )
                appendLog(timedOutRes)
                return@withContext timedOutRes
            }

            val (exitCode, outPair, errPair) = result
            val stdoutText = outPair.first
            val stderrText = errPair.first
            val combinedLower = (stderrText + "\n" + stdoutText).lowercase()
            val denied = exitCode != 0 && (
                combinedLower.contains("permission denied") ||
                    combinedLower.contains("operation not permitted") ||
                    combinedLower.contains("selinux") ||
                    combinedLower.contains("avc: denied") ||
                    (useRoot && (combinedLower.contains("denied") || combinedLower.contains("not allowed")))
                )

            val finalRes = ShellExecutionResult(
                exitCode = exitCode,
                stdout = stdoutText,
                stderr = stderrText,
                truncated = outPair.second || errPair.second,
                timedOut = false,
                denied = denied,
                usedRoot = useRoot,
                durationMs = elapsedMs,
                commandDisplay = spec.displayName
            )
            appendLog(finalRes)
            finalRes
        } catch (e: CancellationException) {
            process?.destroyForcibly()
            throw e
        } catch (e: Exception) {
            process?.destroyForcibly()
            val elapsedMs = ((System.nanoTime() - startNanos) / 1_000_000L).coerceAtLeast(0L)
            val msg = e.localizedMessage ?: "Execution failed"
            val denied = msg.lowercase().contains("permission denied")
            val errRes = ShellExecutionResult(
                exitCode = -1,
                stdout = "",
                stderr = msg,
                truncated = false,
                timedOut = false,
                denied = denied,
                usedRoot = useRoot,
                durationMs = elapsedMs,
                commandDisplay = spec.displayName
            )
            appendLog(errRes)
            errRes
        }
    }

    private fun buildArgv(spec: ShellCommandSpec): List<String> = when (spec) {
        ShellCommandSpec.IdCommand -> listOf("id")
        ShellCommandSpec.GetEnforce -> listOf("getenforce")
        ShellCommandSpec.GetPropAll -> listOf("getprop")
        ShellCommandSpec.ServiceList -> listOf("service", "list")
        is ShellCommandSpec.Dumpsys -> listOf("dumpsys", spec.serviceName.cliName)
        ShellCommandSpec.LshalList -> listOf("lshal", "--neat")
        is ShellCommandSpec.CmdOverlayList -> listOf("cmd", "overlay", "list", "--user", spec.userId.toString())
        is ShellCommandSpec.ReadSystemFile -> listOf("cat", spec.path.value)
        is ShellCommandSpec.ListSystemDir -> {
            val boundedDepth = spec.maxDepth.coerceIn(1, 3)
            listOf("find", spec.path.value, "-maxdepth", boundedDepth.toString())
        }
        is ShellCommandSpec.LogcatSnapshot -> {
            val safeBuffers = spec.buffers.filter { it in ALLOWED_LOGCAT_BUFFERS }
                .ifEmpty { listOf("main", "system") }
            val boundedLines = spec.lines.coerceIn(50, 1500)
            buildList {
                add("logcat")
                add("-d")
                add("-v")
                add("threadtime")
                safeBuffers.forEach { buf ->
                    add("-b")
                    add(buf)
                }
                add("-t")
                add(boundedLines.toString())
            }
        }
        is ShellCommandSpec.DmesgTail -> listOf("dmesg")
    }

    private fun readBoundedStream(stream: InputStream, maxBytes: Int): Pair<String, Boolean> {
        val buffer = ByteArray(4096)
        val out = ByteArrayOutputStream()
        var total = 0
        var truncated = false
        while (true) {
            val read = stream.read(buffer)
            if (read == -1) break
            val remaining = maxBytes - total
            if (remaining <= 0) {
                truncated = true
                break
            }
            val toWrite = minOf(read, remaining)
            out.write(buffer, 0, toWrite)
            total += toWrite
            if (toWrite < read) {
                truncated = true
                break
            }
        }
        return String(out.toByteArray(), StandardCharsets.UTF_8) to truncated
    }

    private fun appendLog(result: ShellExecutionResult) {
        val entry = ShellLogEntry(
            civilTimestampMs = System.currentTimeMillis(),
            commandDisplay = result.commandDisplay,
            usedRoot = result.usedRoot,
            exitCode = result.exitCode,
            timedOut = result.timedOut,
            denied = result.denied,
            outputBytes = result.stdout.length + result.stderr.length
        )
        _recentLogs.update { current ->
            (listOf(entry) + current).take(100)
        }
    }

    companion object {
        private val ALLOWED_LOGCAT_BUFFERS = setOf("main", "system", "events", "crash", "radio")

        private val SU_CANDIDATE_PATHS = listOf(
            "/system/bin/su",
            "/system/xbin/su",
            "/sbin/su",
            "/su/bin/su",
            "/vendor/bin/su",
            "/apex/com.android.runtime/bin/su",
            "/debug_ramdisk/su",
            "/data/adb/ksu/bin/su",
            "/data/adb/ap/bin/su",
            "/data/adb/magisk/su"
        )

        fun findDefaultSuBinary(): String? {
            SU_CANDIDATE_PATHS.firstOrNull { path ->
                runCatching {
                    val f = File(path)
                    f.exists() && f.canExecute()
                }.getOrDefault(false)
            }?.let { return it }

            val pathEnv = System.getenv("PATH").orEmpty()
            for (dir in pathEnv.split(":")) {
                if (dir.isBlank()) continue
                val candidate = File(dir, "su")
                val ok = runCatching { candidate.exists() && candidate.canExecute() }.getOrDefault(false)
                if (ok) return candidate.absolutePath
            }
            return null
        }
    }
}
