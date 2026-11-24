package com.example.fodtracer.system.shell

import com.example.fodtracer.domain.interfaces.*
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.runInterruptible
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileInputStream
import java.io.InputStream
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean

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

        val resolvedSu = if (useRoot) suBinaryResolver() else null
        // Even if File.exists()/canExecute() returns null under mount-namespace/SELinux hiding
        // (common on KernelSU/APatch/Zygisk), still attempt executing "su" directly when suBinaryResolver
        // uses the default lookup, unless a test explicitly injected a null-returning resolver.
        val suExecutable = if (useRoot) {
            resolvedSu ?: if (suBinaryResolver === DEFAULT_SU_RESOLVER) "su" else null
        } else {
            null
        }

        if (useRoot && suExecutable == null) {
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

        executeWithCommand(
            args = args,
            suExecutable = suExecutable,
            useRoot = useRoot,
            timeoutMs = timeoutMs,
            maxOutputBytes = maxOutputBytes,
            displayName = spec.displayName,
            startNanos = startNanos
        )
    }

    /**
     * Tries a specific su binary path (used during interactive Root verification).
     */
    suspend fun executeWithExplicitSu(
        spec: ShellCommandSpec,
        suPath: String,
        timeoutMs: Long = 12_000L,
        maxOutputBytes: Int = 65_536
    ): ShellExecutionResult = withContext(Dispatchers.IO) {
        val args = buildArgv(spec)
        if (args.isEmpty()) {
            return@withContext ShellExecutionResult(
                exitCode = -1,
                stdout = "",
                stderr = "Invalid command spec.",
                truncated = false,
                timedOut = false,
                denied = true,
                usedRoot = true,
                durationMs = 0L,
                commandDisplay = spec.displayName
            )
        }
        executeWithCommand(
            args = args,
            suExecutable = suPath,
            useRoot = true,
            timeoutMs = timeoutMs,
            maxOutputBytes = maxOutputBytes,
            displayName = spec.displayName,
            startNanos = System.nanoTime()
        )
    }

    /**
     * Reads up to [maxBytes] of raw binary bytes from a validated [SafeSystemPath] for ELF/DEX/APK disassembly.
     * Prefers direct read-only stream when accessible, falling back to bounded Root `head -c` if needed.
     */
    suspend fun readBinaryBytes(
        path: SafeSystemPath,
        useRoot: Boolean,
        maxBytes: Int = 4_194_304,
        timeoutMs: Long = 5_500L
    ): ByteArray? = withContext(Dispatchers.IO) {
        val boundedCap = maxBytes.coerceIn(1024, 12_582_912)
        // 1. Direct read-only file access (fast, zero process spawn)
        val direct = runCatching {
            val file = File(path.value)
            if (file.exists() && file.isFile && file.canRead()) {
                FileInputStream(file).use { fis ->
                    readBoundedRawBytes(fis, boundedCap).first
                }
            } else null
        }.getOrNull()
        if (direct != null && direct.isNotEmpty()) return@withContext direct

        if (!useRoot) return@withContext null

        val suCmd = suBinaryResolver() ?: if (suBinaryResolver === DEFAULT_SU_RESOLVER) "su" else return@withContext null
        var process: Process? = null
        try {
            val pb = ProcessBuilder(suCmd, "-c", "head -c $boundedCap ${path.value}")
            pb.redirectErrorStream(false)
            process = pb.start()
            val activeProcess = process
            runCatching { activeProcess.outputStream.close() }

            val timedOut = AtomicBoolean(false)
            val res = coroutineScope {
                val watchdog = launch(Dispatchers.IO) {
                    delay(timeoutMs)
                    timedOut.set(true)
                    killAndCloseStreams(activeProcess)
                }
                try {
                    val outJob = async(Dispatchers.IO) { readBoundedRawBytes(activeProcess.inputStream, boundedCap) }
                    val errJob = async(Dispatchers.IO) { readBoundedStream(activeProcess.errorStream, 4096) }
                    val exit = runInterruptible(Dispatchers.IO) { activeProcess.waitFor() }
                    val bytes = runCatching { outJob.await().first }.getOrDefault(ByteArray(0))
                    runCatching { errJob.await() }
                    if (!timedOut.get() && (exit == 0 || bytes.isNotEmpty())) bytes else null
                } finally {
                    watchdog.cancel()
                }
            }
            res?.takeIf { it.isNotEmpty() }
        } catch (e: CancellationException) {
            process?.let { killAndCloseStreams(it) }
            throw e
        } catch (_: Exception) {
            process?.let { killAndCloseStreams(it) }
            null
        }
    }

    private suspend fun executeWithCommand(
        args: List<String>,
        suExecutable: String?,
        useRoot: Boolean,
        timeoutMs: Long,
        maxOutputBytes: Int,
        displayName: String,
        startNanos: Long
    ): ShellExecutionResult {
        var process: Process? = null
        return try {
            val pb = if (useRoot && suExecutable != null) {
                ProcessBuilder(suExecutable, "-c", args.joinToString(" "))
            } else {
                ProcessBuilder(args)
            }
            pb.redirectErrorStream(false)
            process = pb.start()

            val activeProcess = process
            // Immediately close stdin so su/child processes never wait for interactive input/EOF.
            runCatching { activeProcess.outputStream.close() }

            val timedOut = AtomicBoolean(false)
            val outcome = coroutineScope {
                val watchdog = launch(Dispatchers.IO) {
                    delay(timeoutMs)
                    timedOut.set(true)
                    killAndCloseStreams(activeProcess)
                }
                try {
                    val stdoutJob = async(Dispatchers.IO) {
                        readBoundedStream(activeProcess.inputStream, maxOutputBytes)
                    }
                    val stderrJob = async(Dispatchers.IO) {
                        readBoundedStream(activeProcess.errorStream, (maxOutputBytes / 4).coerceAtLeast(4096))
                    }
                    val exitCode = runInterruptible(Dispatchers.IO) { activeProcess.waitFor() }
                    val out = runCatching { stdoutJob.await() }.getOrElse { "" to false }
                    val err = runCatching { stderrJob.await() }.getOrElse { "" to false }
                    Triple(exitCode, out, err)
                } finally {
                    watchdog.cancel()
                }
            }

            val elapsedMs = ((System.nanoTime() - startNanos) / 1_000_000L).coerceAtLeast(0L)
            if (timedOut.get()) {
                val timedOutRes = ShellExecutionResult(
                    exitCode = -1,
                    stdout = outcome.second.first,
                    stderr = "Command timed out after ${timeoutMs}ms.",
                    truncated = true,
                    timedOut = true,
                    denied = false,
                    usedRoot = useRoot,
                    durationMs = elapsedMs,
                    commandDisplay = displayName
                )
                appendLog(timedOutRes)
                return timedOutRes
            }

            val (exitCode, outPair, errPair) = outcome
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
                commandDisplay = displayName
            )
            appendLog(finalRes)
            finalRes
        } catch (e: CancellationException) {
            process?.let { killAndCloseStreams(it) }
            throw e
        } catch (e: Exception) {
            process?.let { killAndCloseStreams(it) }
            val elapsedMs = ((System.nanoTime() - startNanos) / 1_000_000L).coerceAtLeast(0L)
            val msg = e.localizedMessage ?: "Execution failed"
            val denied = msg.lowercase().contains("permission denied") || msg.lowercase().contains("no such file")
            val errRes = ShellExecutionResult(
                exitCode = -1,
                stdout = "",
                stderr = msg,
                truncated = false,
                timedOut = false,
                denied = denied,
                usedRoot = useRoot,
                durationMs = elapsedMs,
                commandDisplay = displayName
            )
            appendLog(errRes)
            errRes
        }
    }

    private fun killAndCloseStreams(process: Process) {
        runCatching { process.destroyForcibly() }
        runCatching { process.inputStream.close() }
        runCatching { process.errorStream.close() }
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
        is ShellCommandSpec.ReadSystemHead -> {
            val boundedLines = spec.lines.coerceIn(1, 1200)
            listOf("head", "-n", boundedLines.toString(), spec.path.value)
        }
        is ShellCommandSpec.ListSystemDir -> {
            val boundedDepth = spec.maxDepth.coerceIn(1, 4)
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
        is ShellCommandSpec.ReadSystemBinaryBase64 -> {
            val count = spec.maxBytes.coerceIn(1024, 2_097_152)
            listOf("head", "-c", count.toString(), spec.path.value)
        }
        is ShellCommandSpec.ListProcesses -> listOf("ps", "-A", "-o", "PID,NAME")
        is ShellCommandSpec.InspectProcPid -> {
            if (spec.pid <= 0) emptyList()
            else when (spec.target) {
                AllowedProcTarget.FD -> listOf("ls", "-l", "/proc/${spec.pid}/fd")
                AllowedProcTarget.MAPS -> listOf("cat", "/proc/${spec.pid}/maps")
                AllowedProcTarget.CMDLINE -> listOf("cat", "/proc/${spec.pid}/cmdline")
                AllowedProcTarget.STATUS -> listOf("cat", "/proc/${spec.pid}/status")
                AllowedProcTarget.STACK -> listOf("cat", "/proc/${spec.pid}/stack")
                AllowedProcTarget.WCHAN -> listOf("cat", "/proc/${spec.pid}/wchan")
                AllowedProcTarget.SYSCALL -> listOf("cat", "/proc/${spec.pid}/syscall")
            }
        }
    }

    /**
     * Reads up to [maxBytes] into memory, then drains remaining bytes until EOF (without retaining them)
     * so child processes never block on a full stdout/stderr kernel pipe before exiting.
     */
    private fun readBoundedRawBytes(stream: InputStream, maxBytes: Int): Pair<ByteArray, Boolean> {
        val buffer = ByteArray(8192)
        val out = ByteArrayOutputStream()
        var retained = 0
        var truncated = false
        try {
            while (true) {
                val read = stream.read(buffer)
                if (read == -1) break
                val remaining = maxBytes - retained
                if (remaining > 0) {
                    val toWrite = minOf(read, remaining)
                    out.write(buffer, 0, toWrite)
                    retained += toWrite
                    if (toWrite < read) {
                        truncated = true
                    }
                } else {
                    truncated = true
                }
            }
        } catch (_: Exception) {
            // Stream closed forcibly on timeout or process kill
        }
        return out.toByteArray() to truncated
    }

    private fun readBoundedStream(stream: InputStream, maxBytes: Int): Pair<String, Boolean> {
        val (bytes, truncated) = readBoundedRawBytes(stream, maxBytes)
        return String(bytes, StandardCharsets.UTF_8) to truncated
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
            (listOf(entry) + current).take(120)
        }
    }

    companion object {
        private val ALLOWED_LOGCAT_BUFFERS = setOf("main", "system", "events", "crash", "radio")

        val SU_CANDIDATE_PATHS = listOf(
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

        private val DEFAULT_SU_RESOLVER: () -> String? = ::findDefaultSuBinary

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
