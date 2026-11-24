package com.example.fodtracer.data.archives

import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import com.example.fodtracer.data.serialization.FodJson
import com.example.fodtracer.data.serialization.ReportAnonymizer
import com.example.fodtracer.domain.interfaces.ArchiveRepository
import com.example.fodtracer.domain.models.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.*
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream

class ArchiveManager(
    private val context: Context
) : ArchiveRepository {

    private fun privateRootDir(): File = File(context.filesDir, "FODtracer").apply { mkdirs() }

    private fun publicRootDirIfWritable(): File? {
        val granted = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            Environment.isExternalStorageManager()
        } else {
            true
        }
        if (!granted) return null
        return runCatching {
            val dir = File(Environment.getExternalStorageDirectory(), "FODtracer")
            if (!dir.exists()) dir.mkdirs()
            if (dir.exists() && dir.canWrite()) dir else null
        }.getOrNull()
    }

    fun persistStructuredSessionDir(session: DiagnosticSession) {
        val roots = listOfNotNull(privateRootDir(), publicRootDirIfWritable())
        val filesMap = buildStructuredFileMap(session)
        roots.forEach { root ->
            runCatching {
                val diagDir = File(File(root, "diagnostics"), session.sessionId)
                diagDir.mkdirs()
                filesMap.forEach { (relPath, content) ->
                    val outFile = File(diagDir, relPath)
                    outFile.parentFile?.mkdirs()
                    outFile.writeText(content, StandardCharsets.UTF_8)
                }
            }
        }
    }

    fun persistComparisonReport(report: ComparisonReport) {
        val roots = listOfNotNull(privateRootDir(), publicRootDirIfWritable())
        val json = FodJson.codec.encodeToString(report)
        roots.forEach { root ->
            runCatching {
                val cmpDir = File(root, "comparisons").apply { mkdirs() }
                File(cmpDir, "${report.comparisonId}.json").writeText(json, StandardCharsets.UTF_8)
            }
        }
    }

    override suspend fun exportDiagnosticZip(
        session: DiagnosticSession,
        anonymize: Boolean,
        destinationUri: Uri?
    ): Result<String> = withContext(Dispatchers.IO) {
        runCatching {
            val exportSession = if (anonymize) ReportAnonymizer.anonymize(session) else session
            val fileMap = buildStructuredFileMap(exportSession)
            val fileName = "${exportSession.sessionId}${if (anonymize) "_anon" else ""}.fodtracer.zip"

            val zipBytes = createZipBytes(fileMap)

            if (destinationUri != null) {
                context.contentResolver.openOutputStream(destinationUri)?.use { out ->
                    out.write(zipBytes)
                    out.flush()
                } ?: throw IOException("Unable to open SAF destination stream.")
                return@runCatching "SAF:$fileName"
            }

            val targetDir = publicRootDirIfWritable()?.let { File(it, "exports") }
                ?: File(privateRootDir(), "exports")
            targetDir.mkdirs()
            val targetFile = File(targetDir, fileName)
            targetFile.writeBytes(zipBytes)
            targetFile.absolutePath
        }
    }

    override suspend fun importDiagnosticZip(sourceUri: Uri): Result<DiagnosticSession> = withContext(Dispatchers.IO) {
        runCatching {
            context.contentResolver.openInputStream(sourceUri)?.use { input ->
                parseAndVerifyZipStream(input)
            } ?: throw IOException("Cannot open selected ZIP URI.")
        }
    }

    override suspend fun listPublicArchives(): List<String> = withContext(Dispatchers.IO) {
        val dirs = listOfNotNull(
            publicRootDirIfWritable()?.let { File(it, "exports") },
            File(privateRootDir(), "exports")
        )
        dirs.flatMap { dir ->
            dir.listFiles { file -> file.isFile && file.name.endsWith(".zip", ignoreCase = true) }
                ?.map { it.absolutePath }
                .orEmpty()
        }.distinct()
    }

    override suspend fun importPublicArchiveByName(fileName: String): Result<DiagnosticSession> = withContext(Dispatchers.IO) {
        runCatching {
            val file = File(fileName)
            if (!file.exists() || !file.isFile) throw FileNotFoundException("Archive not found: $fileName")
            FileInputStream(file).use { parseAndVerifyZipStream(it) }
        }
    }

    fun buildStructuredFileMap(session: DiagnosticSession): LinkedHashMap<String, String> {
        val map = linkedMapOf<String, String>()
        map["environment.json"] = FodJson.codec.encodeToString(session.environment)
        map["discovery.json"] = FodJson.codec.encodeToString(session.probeResults)
        map["components.json"] = FodJson.codec.encodeToString(session.components)
        map["dependencies.json"] = FodJson.codec.encodeToString(session.dependencies)
        map["evidence.json"] = FodJson.codec.encodeToString(session.evidence)
        map["timeline.json"] = FodJson.codec.encodeToString(session.liveTrace)
        map["anomalies.json"] = FodJson.codec.encodeToString(session.anomalies)
        map["hypotheses.json"] = FodJson.codec.encodeToString(session.hypotheses)
        map["solutions.json"] = FodJson.codec.encodeToString(session.solutions)
        map["disassembly.json"] = FodJson.codec.encodeToString(session.disassembledArtifacts)
        map["mechanism.json"] = FodJson.codec.encodeToString(session.mechanismSteps)
        map["session.json"] = FodJson.codec.encodeToString(session)
        session.rawArtifacts.forEach { (rawName, rawContent) ->
            val cleaned = rawName.trimStart('/').replace("..", "_")
            val targetPath = when {
                cleaned.startsWith("disassembly/") -> cleaned
                cleaned.startsWith("raw/") -> cleaned
                else -> "raw/$cleaned"
            }
            map[targetPath] = rawContent
        }

        val hashes = linkedMapOf<String, String>()
        var totalBytes = 0L
        map.forEach { (name, content) ->
            val bytes = content.toByteArray(StandardCharsets.UTF_8)
            totalBytes += bytes.size
            hashes[name] = sha256Hex(bytes)
        }

        val manifest = ArchiveManifest(
            schemaVersion = session.schemaVersion,
            sessionId = session.sessionId,
            label = session.label,
            createdAtCivilMs = session.createdAtCivilMs,
            appVersionName = "1.0",
            deviceModel = "${session.environment.manufacturer} ${session.environment.model}",
            androidVersion = session.environment.androidVersion,
            romType = session.environment.detectedRomType,
            hasLiveTrace = session.liveTrace != null,
            isAnonymized = session.isAnonymized,
            fileSha256 = hashes,
            totalUncompressedBytes = totalBytes
        )
        map["manifest.json"] = FodJson.codec.encodeToString(manifest)
        return map
    }

    fun createZipBytes(files: Map<String, String>): ByteArray {
        val baos = ByteArrayOutputStream()
        ZipOutputStream(BufferedOutputStream(baos)).use { zos ->
            files.forEach { (name, content) ->
                val entry = ZipEntry(name)
                zos.putNextEntry(entry)
                zos.write(content.toByteArray(StandardCharsets.UTF_8))
                zos.closeEntry()
            }
        }
        return baos.toByteArray()
    }

    /**
     * Hardened ZIP reader preventing Zip-Slip, ZIP bombs, duplicate entries, invalid schemas, and tampered hashes.
     */
    fun parseAndVerifyZipStream(inputStream: InputStream): DiagnosticSession {
        val entriesMap = linkedMapOf<String, ByteArray>()
        var totalUncompressedBytes = 0L
        var entryCount = 0
        val virtualBase = File("/virtual_root").canonicalFile

        ZipInputStream(BufferedInputStream(inputStream)).use { zis ->
            var entry: ZipEntry? = zis.nextEntry
            while (entry != null) {
                entryCount += 1
                if (entryCount > MAX_ZIP_ENTRIES) {
                    throw SecurityException("Archive exceeds maximum entry limit ($MAX_ZIP_ENTRIES).")
                }

                val name = entry.name
                // Zip-Slip & path normalization verification
                if (name.isBlank() || name.startsWith("/") || name.startsWith("\\") || name.contains("..")) {
                    throw SecurityException("Rejected unsafe ZIP entry path: $name")
                }
                val resolved = File(virtualBase, name).canonicalFile
                if (!resolved.path.startsWith(virtualBase.path + File.separator)) {
                    throw SecurityException("Zip-Slip traversal attempt detected: $name")
                }

                if (!entry.isDirectory) {
                    if (entriesMap.containsKey(name)) {
                        throw SecurityException("Duplicate ZIP entry detected: $name")
                    }
                    val baos = ByteArrayOutputStream()
                    val buf = ByteArray(4096)
                    var entryBytes = 0L
                    while (true) {
                        val read = zis.read(buf)
                        if (read == -1) break
                        entryBytes += read
                        totalUncompressedBytes += read
                        if (entryBytes > MAX_SINGLE_ENTRY_BYTES || totalUncompressedBytes > MAX_TOTAL_UNCOMPRESSED_BYTES) {
                            throw SecurityException("ZIP bomb protection triggered: archive exceeds size limits.")
                        }
                        baos.write(buf, 0, read)
                    }
                    entriesMap[name] = baos.toByteArray()
                }
                zis.closeEntry()
                entry = zis.nextEntry
            }
        }

        val manifestBytes = entriesMap["manifest.json"]
            ?: throw SecurityException("Invalid FodTracer archive: missing manifest.json.")
        val manifest = FodJson.codec.decodeFromString<ArchiveManifest>(
            String(manifestBytes, StandardCharsets.UTF_8)
        )

        if (manifest.schemaVersion < 1 || manifest.schemaVersion > FODTRACER_SCHEMA_VERSION) {
            throw SecurityException("Incompatible archive schemaVersion: ${manifest.schemaVersion}")
        }

        // Verify SHA-256 integrity of every file declared in manifest
        manifest.fileSha256.forEach { (fileName, expectedHash) ->
            val fileBytes = entriesMap[fileName]
                ?: throw SecurityException("Archive integrity failure: missing file $fileName declared in manifest.")
            val actualHash = sha256Hex(fileBytes)
            if (!actualHash.equals(expectedHash, ignoreCase = true)) {
                throw SecurityException("SHA-256 checksum mismatch for $fileName.")
            }
        }

        // Reconstruct DiagnosticSession cleanly (preferring session.json, or assembling modular JSON parts)
        val sessionBytes = entriesMap["session.json"]
        if (sessionBytes != null) {
            return FodJson.codec.decodeFromString<DiagnosticSession>(
                String(sessionBytes, StandardCharsets.UTF_8)
            )
        }

        val env = FodJson.codec.decodeFromString<DeviceEnvironment>(
            String(entriesMap["environment.json"] ?: throw SecurityException("Missing environment.json"), StandardCharsets.UTF_8)
        )
        val probes = FodJson.codec.decodeFromString<List<ProbeResult>>(
            String(entriesMap["discovery.json"] ?: throw SecurityException("Missing discovery.json"), StandardCharsets.UTF_8)
        )
        val components = FodJson.codec.decodeFromString<List<DiscoveredComponent>>(
            String(entriesMap["components.json"] ?: throw SecurityException("Missing components.json"), StandardCharsets.UTF_8)
        )
        val deps = FodJson.codec.decodeFromString<List<DependencyLink>>(
            String(entriesMap["dependencies.json"] ?: throw SecurityException("Missing dependencies.json"), StandardCharsets.UTF_8)
        )
        val evidence = FodJson.codec.decodeFromString<List<EvidenceRecord>>(
            String(entriesMap["evidence.json"] ?: throw SecurityException("Missing evidence.json"), StandardCharsets.UTF_8)
        )
        val timeline = entriesMap["timeline.json"]?.let {
            FodJson.codec.decodeFromString<LiveTraceData?>(String(it, StandardCharsets.UTF_8))
        }
        val anomalies = FodJson.codec.decodeFromString<List<AnomalyRecord>>(
            String(entriesMap["anomalies.json"] ?: throw SecurityException("Missing anomalies.json"), StandardCharsets.UTF_8)
        )
        val hypotheses = FodJson.codec.decodeFromString<List<HypothesisRecord>>(
            String(entriesMap["hypotheses.json"] ?: throw SecurityException("Missing hypotheses.json"), StandardCharsets.UTF_8)
        )
        val solutions = FodJson.codec.decodeFromString<List<SolutionProposal>>(
            String(entriesMap["solutions.json"] ?: throw SecurityException("Missing solutions.json"), StandardCharsets.UTF_8)
        )
        val disassembled = entriesMap["disassembly.json"]?.let {
            FodJson.codec.decodeFromString<List<DisassembledArtifact>>(String(it, StandardCharsets.UTF_8))
        }.orEmpty()
        val mechanism = entriesMap["mechanism.json"]?.let {
            FodJson.codec.decodeFromString<List<FodMechanismStep>>(String(it, StandardCharsets.UTF_8))
        }.orEmpty()

        return DiagnosticSession(
            schemaVersion = manifest.schemaVersion,
            sessionId = manifest.sessionId,
            label = manifest.label,
            createdAtCivilMs = manifest.createdAtCivilMs,
            updatedAtCivilMs = manifest.createdAtCivilMs,
            environment = env,
            probeResults = probes,
            components = components,
            dependencies = deps,
            evidence = evidence,
            liveTrace = timeline,
            anomalies = anomalies,
            hypotheses = hypotheses,
            solutions = solutions,
            isAnonymized = manifest.isAnonymized,
            disassembledArtifacts = disassembled,
            mechanismSteps = mechanism
        )
    }

    private fun sha256Hex(bytes: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(bytes)
        return digest.joinToString("") { "%02x".format(it) }
    }

    companion object {
        private const val MAX_ZIP_ENTRIES = 256
        private const val MAX_SINGLE_ENTRY_BYTES = 8L * 1024L * 1024L
        private const val MAX_TOTAL_UNCOMPRESSED_BYTES = 24L * 1024L * 1024L
    }
}
