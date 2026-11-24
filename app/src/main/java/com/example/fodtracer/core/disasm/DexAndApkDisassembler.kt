package com.example.fodtracer.core.disasm

import com.example.fodtracer.domain.models.ArtifactKind
import com.example.fodtracer.domain.models.DisassembledArtifact
import com.example.fodtracer.domain.models.EpistemicLevel
import com.example.fodtracer.domain.models.PartitionOrigin
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.util.zip.ZipInputStream

/**
 * Pure-Kotlin APK/JAR/DEX/RRO disassembler & analyzer.
 * Parses DEX headers, string/type/method tables, class_defs, and Dalvik bytecode instructions
 * for FOD/UDFPS/Biometric/HBM classes — 100% read-only without executing or loading external code.
 */
object DexAndApkDisassembler {

    private val FOD_CLASS_KEYWORDS = listOf(
        "udfps", "fod", "fingerprint", "biometric", "authcontroller",
        "hbm", "lhbm", "displaypower", "doze", "phh", "treble"
    )

    private val FOD_RESOURCE_KEYWORDS = listOf(
        "udfps", "fod", "fingerprint", "biometric", "hbm", "lhbm",
        "doze", "aod", "dim", "brightness", "overlay", "sensor"
    )

    fun analyzeApkOrJar(
        id: String,
        path: String,
        partition: PartitionOrigin,
        isOverlay: Boolean,
        zipBytes: ByteArray
    ): Pair<DisassembledArtifact, String>? {
        val dexEntries = linkedMapOf<String, ByteArray>()
        var resourcesBytes: ByteArray? = null
        var manifestBytes: ByteArray? = null

        runCatching {
            ZipInputStream(ByteArrayInputStream(zipBytes)).use { zis ->
                var entry = zis.nextEntry
                var count = 0
                while (entry != null && count < 2048) {
                    count++
                    val name = entry.name
                    when {
                        name.matches(Regex("^classes\\d*\\.dex$")) && dexEntries.size < 3 -> {
                            dexEntries[name] = readBounded(zis, 4_194_304)
                        }
                        name == "resources.arsc" && resourcesBytes == null -> {
                            resourcesBytes = readBounded(zis, 2_097_152)
                        }
                        name == "AndroidManifest.xml" && manifestBytes == null -> {
                            manifestBytes = readBounded(zis, 524_288)
                        }
                    }
                    zis.closeEntry()
                    entry = zis.nextEntry
                }
            }
        }

        if (dexEntries.isEmpty() && resourcesBytes == null && manifestBytes == null) return null

        val manifestStrings = manifestBytes?.let { extractPrintableStrings(it, FOD_RESOURCE_KEYWORDS + listOf("package", "target", "systemui", "android"), 40) }.orEmpty()
        val resourceStrings = resourcesBytes?.let { extractPrintableStrings(it, FOD_RESOURCE_KEYWORDS, 80) }.orEmpty()

        val allClassSummaries = mutableListOf<String>()
        val allDisasm = StringBuilder()
        allDisasm.appendLine("=== FodTracer APK/DEX/RRO Analysis ===")
        allDisasm.appendLine("File: $path")
        allDisasm.appendLine("Kind: ${if (isOverlay) "RRO_OVERLAY" else "APK_DEX"} | DEX files: ${dexEntries.keys.joinToString()}")
        if (manifestStrings.isNotEmpty()) {
            allDisasm.appendLine("\n[AndroidManifest Strings]")
            manifestStrings.forEach { allDisasm.appendLine("  $it") }
        }
        if (resourceStrings.isNotEmpty()) {
            allDisasm.appendLine("\n[resources.arsc FOD/UDFPS Config Strings]")
            resourceStrings.forEach { allDisasm.appendLine("  $it") }
        }

        dexEntries.forEach { (dexName, dexBytes) ->
            val dexParsed = parseDexBytes(dexName, dexBytes)
            if (dexParsed != null) {
                allClassSummaries += dexParsed.classSummaries
                allDisasm.appendLine()
                allDisasm.append(dexParsed.disassemblyReport)
            }
        }

        val fullReport = allDisasm.toString()
        val rawFileName = "disassembly/${path.trim('/').replace('/', '_')}.dex.txt"
        val combinedStrings = (manifestStrings + resourceStrings).distinct().take(80)

        val artifact = DisassembledArtifact(
            id = id,
            name = path.substringAfterLast('/'),
            path = path,
            partition = partition,
            kind = if (isOverlay) ArtifactKind.RRO_OVERLAY else ArtifactKind.APK_DEX,
            architecture = "Dalvik/DEX",
            neededLibraries = dexEntries.keys.toList(),
            keySymbols = allClassSummaries.distinct().take(80),
            extractedStrings = combinedStrings,
            disassemblySnippet = fullReport.lines().take(60).joinToString("\n"),
            epistemicLevel = EpistemicLevel.PROVED,
            rawFileName = rawFileName
        )
        return artifact to fullReport
    }

    data class DexParseOutput(
        val classSummaries: List<String>,
        val disassemblyReport: String
    )

    fun parseDexBytes(dexName: String, bytes: ByteArray): DexParseOutput? {
        if (bytes.size < 112) return null
        if (bytes[0] != 'd'.code.toByte() || bytes[1] != 'e'.code.toByte() || bytes[2] != 'x'.code.toByte()) {
            return null
        }

        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsSize = buf.getInt(56).coerceIn(0, 200_000)
        val stringIdsOff = buf.getInt(60)
        val typeIdsSize = buf.getInt(64).coerceIn(0, 100_000)
        val typeIdsOff = buf.getInt(68)
        val fieldIdsSize = buf.getInt(76).coerceIn(0, 150_000)
        val fieldIdsOff = buf.getInt(80)
        val methodIdsSize = buf.getInt(84).coerceIn(0, 200_000)
        val methodIdsOff = buf.getInt(88)
        val classDefsSize = buf.getInt(96).coerceIn(0, 50_000)
        val classDefsOff = buf.getInt(100)

        val strings = Array(stringIdsSize) { idx ->
            val off = stringIdsOff + idx * 4
            if (off + 4 > bytes.size) "" else readMutf8String(bytes, buf.getInt(off))
        }

        fun typeName(typeIdx: Int): String {
            if (typeIdx !in 0 until typeIdsSize) return "?"
            val off = typeIdsOff + typeIdx * 4
            if (off + 4 > bytes.size) return "?"
            val strIdx = buf.getInt(off)
            return strings.getOrElse(strIdx) { "?" }
        }

        fun methodName(methodIdx: Int): String {
            if (methodIdx !in 0 until methodIdsSize) return "method@$methodIdx"
            val off = methodIdsOff + methodIdx * 8
            if (off + 8 > bytes.size) return "method@$methodIdx"
            val clsIdx = buf.getShort(off).toInt() and 0xFFFF
            val nameStrIdx = buf.getInt(off + 4)
            val cls = typeName(clsIdx).removePrefix("L").removeSuffix(";").replace('/', '.')
            val mName = strings.getOrElse(nameStrIdx) { "?" }
            return "$cls->$mName"
        }

        fun fieldName(fieldIdx: Int): String {
            if (fieldIdx !in 0 until fieldIdsSize) return "field@$fieldIdx"
            val off = fieldIdsOff + fieldIdx * 8
            if (off + 8 > bytes.size) return "field@$fieldIdx"
            val clsIdx = buf.getShort(off).toInt() and 0xFFFF
            val nameStrIdx = buf.getInt(off + 4)
            val cls = typeName(clsIdx).removePrefix("L").removeSuffix(";").replace('/', '.')
            val fName = strings.getOrElse(nameStrIdx) { "?" }
            return "$cls.$fName"
        }

        val summaries = mutableListOf<String>()
        val report = StringBuilder()
        report.appendLine("--- DEX: $dexName (classes=$classDefsSize, methods=$methodIdsSize) ---")

        var analyzedClasses = 0
        for (i in 0 until classDefsSize) {
            val base = classDefsOff + i * 32
            if (base + 32 > bytes.size) break
            val classIdx = buf.getInt(base)
            val rawDesc = typeName(classIdx)
            val className = rawDesc.removePrefix("L").removeSuffix(";").replace('/', '.')
            if (!FOD_CLASS_KEYWORDS.any { className.contains(it, ignoreCase = true) }) continue

            analyzedClasses++
            if (analyzedClasses > 25) break

            val superIdx = buf.getInt(base + 8)
            val superName = if (superIdx >= 0) typeName(superIdx).removePrefix("L").removeSuffix(";").replace('/', '.') else "Object"
            val classDataOff = buf.getInt(base + 24)

            summaries += className
            report.appendLine("\nclass $className extends $superName")

            if (classDataOff in 1 until bytes.size) {
                parseClassDataAndDisassemble(
                    bytes = bytes,
                    buf = buf,
                    startOff = classDataOff,
                    strings = strings,
                    methodLookup = ::methodName,
                    fieldLookup = ::fieldName,
                    outReport = report,
                    outSummaries = summaries
                )
            }
        }

        return DexParseOutput(summaries, report.toString())
    }

    private fun parseClassDataAndDisassemble(
        bytes: ByteArray,
        buf: ByteBuffer,
        startOff: Int,
        strings: Array<String>,
        methodLookup: (Int) -> String,
        fieldLookup: (Int) -> String,
        outReport: StringBuilder,
        outSummaries: MutableList<String>
    ) {
        val pos = intArrayOf(startOff)
        val staticFields = readUleb128(bytes, pos)
        val instanceFields = readUleb128(bytes, pos)
        val directMethods = readUleb128(bytes, pos)
        val virtualMethods = readUleb128(bytes, pos)

        var fieldIdx = 0
        repeat((staticFields + instanceFields).coerceAtMost(200)) {
            if (pos[0] >= bytes.size) return
            fieldIdx += readUleb128(bytes, pos)
            readUleb128(bytes, pos) // accessFlags
        }

        var directIdx = 0
        var virtualIdx = 0
        val methodsToDecode = mutableListOf<Pair<Int, Int>>()

        repeat(directMethods.coerceAtMost(200)) {
            if (pos[0] >= bytes.size) return
            directIdx += readUleb128(bytes, pos)
            readUleb128(bytes, pos) // accessFlags
            val codeOff = readUleb128(bytes, pos)
            methodsToDecode += directIdx to codeOff
        }
        repeat(virtualMethods.coerceAtMost(200)) {
            if (pos[0] >= bytes.size) return
            virtualIdx += readUleb128(bytes, pos)
            readUleb128(bytes, pos) // accessFlags
            val codeOff = readUleb128(bytes, pos)
            methodsToDecode += virtualIdx to codeOff
        }

        var decodedMethods = 0
        for ((mIdx, codeOff) in methodsToDecode) {
            val sig = methodLookup(mIdx)
            val mShort = sig.substringAfter("->")
            outSummaries += sig
            if (codeOff <= 0 || codeOff + 16 > bytes.size || decodedMethods >= 8) {
                outReport.appendLine("  .method $mShort")
                continue
            }
            val interestingMethod = FOD_CLASS_KEYWORDS.any { mShort.contains(it, true) } ||
                mShort.contains("on", true) || mShort.contains("set", true) || mShort.contains("show", true)
            if (!interestingMethod) {
                outReport.appendLine("  .method $mShort")
                continue
            }

            decodedMethods++
            val insnsSize = buf.getInt(codeOff + 12).coerceIn(0, 128)
            val insnsStart = codeOff + 16
            outReport.appendLine("  .method $mShort (insns=$insnsSize)")

            var pc = 0
            while (pc < insnsSize && insnsStart + (pc + 1) * 2 <= bytes.size) {
                val unit0 = buf.getShort(insnsStart + pc * 2).toInt() and 0xFFFF
                val op = unit0 and 0xFF
                val step = dalvikInsnWidth(op)
                val line = decodeDalvikInsn(op, unit0, insnsStart, pc, buf, strings, methodLookup, fieldLookup)
                if (line != null) {
                    outReport.appendLine("    0x${pc.toString(16).padStart(4, '0')}: $line")
                }
                pc += step.coerceAtLeast(1)
            }
        }
    }

    private fun decodeDalvikInsn(
        op: Int,
        unit0: Int,
        insnsStart: Int,
        pc: Int,
        buf: ByteBuffer,
        strings: Array<String>,
        methodLookup: (Int) -> String,
        fieldLookup: (Int) -> String
    ): String? {
        fun u16(offset: Int): Int {
            val pos = insnsStart + (pc + offset) * 2
            return if (pos + 2 <= buf.limit()) buf.getShort(pos).toInt() and 0xFFFF else 0
        }
        return when (op) {
            0x0E -> "return-void"
            0x0F, 0x10, 0x11 -> "return v${(unit0 ushr 8) and 0xFF}"
            0x1A -> { // const-string vAA, string@BBBB
                val sIdx = u16(1)
                "const-string v${(unit0 ushr 8) and 0xFF}, \"${strings.getOrElse(sIdx) { "?" }.take(100)}\""
            }
            0x1B -> { // const-string/jumbo
                val pos = insnsStart + (pc + 1) * 2
                val sIdx = if (pos + 4 <= buf.limit()) buf.getInt(pos) else 0
                "const-string/jumbo \"${strings.getOrElse(sIdx) { "?" }.take(100)}\""
            }
            in 0x52..0x5F -> {
                val fIdx = u16(1)
                val opName = if (op <= 0x58) "iget" else "iput"
                "$opName ${fieldLookup(fIdx)}"
            }
            in 0x60..0x6D -> {
                val fIdx = u16(1)
                val opName = if (op <= 0x66) "sget" else "sput"
                "$opName ${fieldLookup(fIdx)}"
            }
            0x6E, 0x6F, 0x70, 0x71, 0x72 -> {
                val mIdx = u16(1)
                val name = when (op) {
                    0x6E -> "invoke-virtual"
                    0x6F -> "invoke-super"
                    0x70 -> "invoke-direct"
                    0x71 -> "invoke-static"
                    else -> "invoke-interface"
                }
                "$name ${methodLookup(mIdx)}"
            }
            in 0x32..0x3D -> "if-cond +${u16(1).toShort()}"
            else -> null
        }
    }

    private fun dalvikInsnWidth(op: Int): Int = when (op) {
        0x00, 0x01, 0x04, 0x07, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x1D, 0x1E, 0x21, 0x27, 0x28 -> 1
        in 0x3E..0x43, in 0x79..0x7A, in 0xB0..0xCF -> 1
        0x14, 0x17, 0x1B, 0x26, 0x2A, 0x2B, 0x2C, in 0x6E..0x78 -> 3
        0x18 -> 5
        else -> 2
    }

    private fun readMutf8String(bytes: ByteArray, dataOff: Int): String {
        if (dataOff !in 0 until bytes.size) return ""
        val pos = intArrayOf(dataOff)
        readUleb128(bytes, pos) // utf16 length
        val start = pos[0]
        var end = start
        while (end < bytes.size && bytes[end] != 0.toByte() && end - start < 240) {
            end++
        }
        return String(bytes, start, (end - start).coerceAtLeast(0), StandardCharsets.UTF_8)
    }

    private fun readUleb128(bytes: ByteArray, pos: IntArray): Int {
        var result = 0
        var shift = 0
        while (pos[0] < bytes.size && shift < 35) {
            val cur = bytes[pos[0]++].toInt() and 0xFF
            result = result or ((cur and 0x7F) shl shift)
            if ((cur and 0x80) == 0) break
            shift += 7
        }
        return result
    }

    private fun readBounded(zis: ZipInputStream, maxBytes: Int): ByteArray {
        val baos = ByteArrayOutputStream()
        val buf = ByteArray(8192)
        var total = 0
        while (total < maxBytes) {
            val r = zis.read(buf, 0, minOf(buf.size, maxBytes - total))
            if (r == -1) break
            baos.write(buf, 0, r)
            total += r
        }
        return baos.toByteArray()
    }

    private fun extractPrintableStrings(bytes: ByteArray, keywords: List<String>, maxCount: Int): List<String> {
        val out = linkedSetOf<String>()
        val sb = StringBuilder()
        for (bRaw in bytes) {
            val b = bRaw.toInt() and 0xFF
            if (b in 0x20..0x7E) {
                if (sb.length < 160) sb.append(b.toChar())
            } else {
                if (sb.length >= 5) {
                    val s = sb.toString()
                    if (keywords.any { s.contains(it, ignoreCase = true) }) {
                        out += s
                        if (out.size >= maxCount) break
                    }
                }
                sb.clear()
            }
        }
        return out.toList()
    }
}
