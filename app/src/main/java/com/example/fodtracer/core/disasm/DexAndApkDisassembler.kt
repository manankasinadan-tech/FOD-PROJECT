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
 * Streams ZIP entries one DEX at a time to minimize heap usage, decodes Android Binary XML (AXML)
 * and compiled resources.arsc typed values, parses DEX tables lazily, and extracts Dalvik bytecode
 * instructions and caller->callee cross-references.
 */
object DexAndApkDisassembler {

    private val FOD_CLASS_KEYWORDS = listOf(
        "udfps", "fod", "fingerprint", "biometric", "authcontroller",
        "hbm", "lhbm", "displaypower", "displaymode", "doze", "phh", "treble",
        "keyguard", "touch", "brightness"
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
        return ZipInputStream(ByteArrayInputStream(zipBytes)).use { zis ->
            analyzeApkOrJarStream(
                id = id,
                path = path,
                partition = partition,
                isOverlay = isOverlay,
                zis = zis
            )
        }
    }

    fun analyzeApkOrJarStream(
        id: String,
        path: String,
        partition: PartitionOrigin,
        isOverlay: Boolean,
        zis: ZipInputStream
    ): Pair<DisassembledArtifact, String>? {
        val dexNamesSeen = mutableListOf<String>()
        val extraXmlEntries = linkedMapOf<String, ByteArray>()
        var resourcesBytes: ByteArray? = null
        var manifestBytes: ByteArray? = null

        val allClassSummaries = mutableListOf<String>()
        val allXrefs = mutableListOf<String>()
        val dexReports = StringBuilder()

        runCatching {
            var entry = zis.nextEntry
            var count = 0
            while (entry != null && count < 8192) {
                count++
                val name = entry.name
                when {
                    name.matches(Regex("^classes\\d*\\.dex$")) && dexNamesSeen.size < 8 -> {
                        dexNamesSeen += name
                        // Stream-process ONE DEX at a time so previous DEX buffers are immediately eligible for GC
                        val dexBytes = readBounded(zis, 6_291_456)
                        if (dexReports.length < 120_000) {
                            runCatching { parseDexBytes(name, dexBytes) }.getOrNull()?.let { dexParsed ->
                                allClassSummaries += dexParsed.classSummaries
                                allXrefs += dexParsed.crossReferences
                                dexReports.appendLine()
                                dexReports.append(dexParsed.disassemblyReport.take(45_000))
                            }
                        }
                    }
                    name == "resources.arsc" && resourcesBytes == null -> {
                        resourcesBytes = readBounded(zis, 4_194_304)
                    }
                    name == "AndroidManifest.xml" && manifestBytes == null -> {
                        manifestBytes = readBounded(zis, 524_288)
                    }
                    name.startsWith("res/xml/") && name.endsWith(".xml") && extraXmlEntries.size < 12 &&
                        FOD_RESOURCE_KEYWORDS.any { name.contains(it, ignoreCase = true) } -> {
                        extraXmlEntries[name] = readBounded(zis, 131_072)
                    }
                }
                zis.closeEntry()
                entry = zis.nextEntry
            }
        }

        if (dexNamesSeen.isEmpty() && resourcesBytes == null && manifestBytes == null && extraXmlEntries.isEmpty()) {
            return null
        }

        val decodedManifestXml = manifestBytes?.let { runCatching { BinaryXmlAndArscDecoder.decodeBinaryXml(it) }.getOrNull() }
        val decodedResXmls = extraXmlEntries.mapNotNull { (entryName, xmlBytes) ->
            val decoded = runCatching { BinaryXmlAndArscDecoder.decodeBinaryXml(xmlBytes) }.getOrNull()
                ?: extractPrintableStrings(xmlBytes, FOD_RESOURCE_KEYWORDS, 25).joinToString("\n")
            if (decoded.isNotBlank()) entryName to decoded else null
        }

        val arscEntries = resourcesBytes?.let {
            runCatching { BinaryXmlAndArscDecoder.extractArscEntries(it, filterFodOnly = !isOverlay) }.getOrDefault(emptyList())
        }.orEmpty()
        val manifestStrings = manifestBytes?.let {
            extractPrintableStrings(it, FOD_RESOURCE_KEYWORDS + listOf("package", "target", "systemui", "android"), 60)
        }.orEmpty()
        val resourceStrings = resourcesBytes?.let {
            extractPrintableStrings(it, FOD_RESOURCE_KEYWORDS, 120)
        }.orEmpty()

        val allDisasm = StringBuilder()
        allDisasm.appendLine("=== FodTracer APK/DEX/RRO Analysis ===")
        allDisasm.appendLine("File: $path")
        allDisasm.appendLine("Kind: ${if (isOverlay) "RRO_OVERLAY" else "APK_DEX"} | DEX files: ${dexNamesSeen.joinToString()}")

        if (!decodedManifestXml.isNullOrBlank()) {
            allDisasm.appendLine("\n[Decoded AndroidManifest.xml (AXML)]")
            allDisasm.appendLine(decodedManifestXml.lines().take(60).joinToString("\n"))
        } else if (manifestStrings.isNotEmpty()) {
            allDisasm.appendLine("\n[AndroidManifest Strings]")
            manifestStrings.forEach { allDisasm.appendLine("  $it") }
        }

        if (arscEntries.isNotEmpty()) {
            allDisasm.appendLine("\n[Decoded resources.arsc Values (${arscEntries.size})]")
            arscEntries.forEach { allDisasm.appendLine("  $it") }
        } else if (resourceStrings.isNotEmpty()) {
            allDisasm.appendLine("\n[resources.arsc FOD/UDFPS Config Strings]")
            resourceStrings.forEach { allDisasm.appendLine("  $it") }
        }

        decodedResXmls.forEach { (name, xmlText) ->
            allDisasm.appendLine("\n[Decoded $name (AXML)]")
            allDisasm.appendLine(xmlText.lines().take(60).joinToString("\n"))
        }

        if (dexReports.isNotEmpty()) {
            allDisasm.append(dexReports)
        }

        val fullReport = allDisasm.toString().take(140_000)
        val rawFileName = "disassembly/${path.trim('/').replace('/', '_')}.dex.txt"
        val combinedStrings = (manifestStrings + resourceStrings).distinct().take(120)
        val decodedResList = buildList {
            addAll(arscEntries)
            decodedManifestXml?.lines()?.filter {
                it.contains("package=", true) || it.contains("targetPackage", true) ||
                    it.contains("FINGERPRINT", true) || it.contains("BIOMETRIC", true)
            }?.take(10)?.forEach { add("manifest: ${it.trim()}") }
            decodedResXmls.forEach { (n, x) ->
                x.lines().take(8).forEach { line ->
                    if (line.isNotBlank()) add("$n: ${line.trim()}")
                }
            }
        }.distinct().take(150)

        val artifact = DisassembledArtifact(
            id = id,
            name = path.substringAfterLast('/'),
            path = path,
            partition = partition,
            kind = if (isOverlay) ArtifactKind.RRO_OVERLAY else ArtifactKind.APK_DEX,
            architecture = "Dalvik/DEX + AXML/ARSC",
            neededLibraries = dexNamesSeen.toList(),
            keySymbols = allClassSummaries.distinct().take(160),
            extractedStrings = combinedStrings,
            disassemblySnippet = fullReport.lines().take(75).joinToString("\n"),
            epistemicLevel = EpistemicLevel.PROVED,
            rawFileName = rawFileName,
            crossReferences = allXrefs.distinct().take(120),
            decodedResources = decodedResList
        )
        return artifact to fullReport
    }

    data class DexParseOutput(
        val classSummaries: List<String>,
        val disassemblyReport: String,
        val crossReferences: List<String> = emptyList()
    )

    fun parseDexBytes(dexName: String, bytes: ByteArray): DexParseOutput? {
        if (bytes.size < 112) return null
        if (bytes[0] != 'd'.code.toByte() || bytes[1] != 'e'.code.toByte() || bytes[2] != 'x'.code.toByte()) {
            return null
        }

        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val stringIdsSize = buf.getInt(56).coerceIn(0, 300_000)
        val stringIdsOff = buf.getInt(60)
        val typeIdsSize = buf.getInt(64).coerceIn(0, 120_000)
        val typeIdsOff = buf.getInt(68)
        val fieldIdsSize = buf.getInt(76).coerceIn(0, 200_000)
        val fieldIdsOff = buf.getInt(80)
        val methodIdsSize = buf.getInt(84).coerceIn(0, 300_000)
        val methodIdsOff = buf.getInt(88)
        val classDefsSize = buf.getInt(96).coerceIn(0, 80_000)
        val classDefsOff = buf.getInt(100)

        // Lazy string lookup avoids allocating 150,000+ String objects per large framework/SystemUI DEX
        val stringCache = HashMap<Int, String>(2048)
        fun readString(idx: Int): String {
            if (idx !in 0 until stringIdsSize || stringIdsOff < 0) return ""
            stringCache[idx]?.let { return it }
            val offLong = stringIdsOff.toLong() + idx.toLong() * 4L
            if (offLong < 0L || offLong + 4L > bytes.size.toLong()) return ""
            val strDataOff = buf.getInt(offLong.toInt())
            val resolved = readMutf8String(bytes, strDataOff)
            if (stringCache.size < 8192) {
                stringCache[idx] = resolved
            }
            return resolved
        }

        fun typeName(typeIdx: Int): String {
            if (typeIdx !in 0 until typeIdsSize || typeIdsOff < 0) return "?"
            val offLong = typeIdsOff.toLong() + typeIdx.toLong() * 4L
            if (offLong < 0L || offLong + 4L > bytes.size.toLong()) return "?"
            val strIdx = buf.getInt(offLong.toInt())
            return readString(strIdx).ifEmpty { "?" }
        }

        fun methodName(methodIdx: Int): String {
            if (methodIdx !in 0 until methodIdsSize || methodIdsOff < 0) return "method@$methodIdx"
            val offLong = methodIdsOff.toLong() + methodIdx.toLong() * 8L
            if (offLong < 0L || offLong + 8L > bytes.size.toLong()) return "method@$methodIdx"
            val off = offLong.toInt()
            val clsIdx = buf.getShort(off).toInt() and 0xFFFF
            val nameStrIdx = buf.getInt(off + 4)
            val cls = typeName(clsIdx).removePrefix("L").removeSuffix(";").replace('/', '.')
            val mName = readString(nameStrIdx).ifEmpty { "?" }
            return "$cls->$mName"
        }

        fun fieldName(fieldIdx: Int): String {
            if (fieldIdx !in 0 until fieldIdsSize || fieldIdsOff < 0) return "field@$fieldIdx"
            val offLong = fieldIdsOff.toLong() + fieldIdx.toLong() * 8L
            if (offLong < 0L || offLong + 8L > bytes.size.toLong()) return "field@$fieldIdx"
            val off = offLong.toInt()
            val clsIdx = buf.getShort(off).toInt() and 0xFFFF
            val nameStrIdx = buf.getInt(off + 4)
            val cls = typeName(clsIdx).removePrefix("L").removeSuffix(";").replace('/', '.')
            val fName = readString(nameStrIdx).ifEmpty { "?" }
            return "$cls.$fName"
        }

        val summaries = mutableListOf<String>()
        val xrefs = mutableListOf<String>()
        val report = StringBuilder()
        report.appendLine("--- DEX: $dexName (classes=$classDefsSize, methods=$methodIdsSize) ---")

        if (classDefsOff >= 0) {
            var analyzedClasses = 0
            for (i in 0 until classDefsSize) {
                val baseLong = classDefsOff.toLong() + i.toLong() * 32L
                if (baseLong < 0L || baseLong + 32L > bytes.size.toLong()) break
                val base = baseLong.toInt()
                val classIdx = buf.getInt(base)
                val rawDesc = typeName(classIdx)
                val className = rawDesc.removePrefix("L").removeSuffix(";").replace('/', '.')
                if (!FOD_CLASS_KEYWORDS.any { className.contains(it, ignoreCase = true) }) continue

                analyzedClasses++
                if (analyzedClasses > 60 || report.length > 42_000) break

                val superIdx = buf.getInt(base + 8)
                val superName = if (superIdx >= 0) typeName(superIdx).removePrefix("L").removeSuffix(";").replace('/', '.') else "Object"
                val classDataOff = buf.getInt(base + 24)

                summaries += className
                report.appendLine("\nclass $className extends $superName")

                if (classDataOff in 1 until bytes.size) {
                    parseClassDataAndDisassemble(
                        className = className,
                        bytes = bytes,
                        buf = buf,
                        startOff = classDataOff,
                        readString = ::readString,
                        methodLookup = ::methodName,
                        fieldLookup = ::fieldName,
                        outReport = report,
                        outSummaries = summaries,
                        outXrefs = xrefs
                    )
                }
            }
        }

        if (xrefs.isNotEmpty()) {
            report.appendLine("\n[DEX Method Cross-References (${xrefs.size})]")
            xrefs.take(80).forEach { report.appendLine("  $it") }
        }

        return DexParseOutput(summaries, report.toString(), xrefs)
    }

    private fun parseClassDataAndDisassemble(
        className: String,
        bytes: ByteArray,
        buf: ByteBuffer,
        startOff: Int,
        readString: (Int) -> String,
        methodLookup: (Int) -> String,
        fieldLookup: (Int) -> String,
        outReport: StringBuilder,
        outSummaries: MutableList<String>,
        outXrefs: MutableList<String>
    ) {
        val pos = intArrayOf(startOff)
        val staticFields = readUleb128(bytes, pos)
        val instanceFields = readUleb128(bytes, pos)
        val directMethods = readUleb128(bytes, pos)
        val virtualMethods = readUleb128(bytes, pos)

        var fieldIdx = 0
        repeat((staticFields + instanceFields).coerceIn(0, 300)) {
            if (pos[0] >= bytes.size) return
            fieldIdx += readUleb128(bytes, pos)
            readUleb128(bytes, pos)
        }

        var directIdx = 0
        var virtualIdx = 0
        val methodsToDecode = mutableListOf<Pair<Int, Int>>()

        repeat(directMethods.coerceIn(0, 300)) {
            if (pos[0] >= bytes.size) return
            directIdx += readUleb128(bytes, pos)
            readUleb128(bytes, pos)
            val codeOff = readUleb128(bytes, pos)
            methodsToDecode += directIdx to codeOff
        }
        repeat(virtualMethods.coerceIn(0, 300)) {
            if (pos[0] >= bytes.size) return
            virtualIdx += readUleb128(bytes, pos)
            readUleb128(bytes, pos)
            val codeOff = readUleb128(bytes, pos)
            methodsToDecode += virtualIdx to codeOff
        }

        var decodedMethods = 0
        for ((mIdx, codeOff) in methodsToDecode) {
            val sig = methodLookup(mIdx)
            val mShort = sig.substringAfter("->")
            outSummaries += sig
            if (codeOff <= 0 || codeOff + 16 > bytes.size || decodedMethods >= 24 || outReport.length > 42_000) {
                outReport.appendLine("  .method $mShort")
                continue
            }
            val interestingMethod = FOD_CLASS_KEYWORDS.any { mShort.contains(it, true) } ||
                mShort.contains("on", true) || mShort.contains("set", true) ||
                mShort.contains("show", true) || mShort.contains("hide", true) ||
                mShort.contains("update", true) || mShort.contains("handle", true)
            if (!interestingMethod) {
                outReport.appendLine("  .method $mShort")
                continue
            }

            decodedMethods++
            val insnsSize = buf.getInt(codeOff + 12).coerceIn(0, 240)
            val insnsStart = codeOff + 16
            outReport.appendLine("  .method $mShort (insns=$insnsSize)")

            val callees = linkedSetOf<String>()
            val literalStrings = linkedSetOf<String>()

            var pc = 0
            while (pc < insnsSize && insnsStart + (pc + 1) * 2 <= bytes.size) {
                val unit0 = buf.getShort(insnsStart + pc * 2).toInt() and 0xFFFF
                val op = unit0 and 0xFF
                val step = dalvikInsnWidth(op)
                val line = decodeDalvikInsn(
                    op = op,
                    unit0 = unit0,
                    insnsStart = insnsStart,
                    pc = pc,
                    buf = buf,
                    readString = readString,
                    methodLookup = methodLookup,
                    fieldLookup = fieldLookup,
                    outCallees = callees,
                    outStrings = literalStrings
                )
                if (line != null) {
                    outReport.appendLine("    0x${pc.toString(16).padStart(4, '0')}: $line")
                }
                pc += step.coerceAtLeast(1)
            }

            if (callees.isNotEmpty() || literalStrings.isNotEmpty()) {
                val parts = buildList {
                    if (callees.isNotEmpty()) add("invokes=[${callees.take(8).joinToString(", ")}]")
                    if (literalStrings.isNotEmpty()) add("strings=[${literalStrings.take(5).joinToString(", ") { "\"$it\"" }}]")
                }
                outXrefs += "${className.substringAfterLast('.')}->$mShort -> ${parts.joinToString(" | ")}"
            }
        }
    }

    private fun decodeDalvikInsn(
        op: Int,
        unit0: Int,
        insnsStart: Int,
        pc: Int,
        buf: ByteBuffer,
        readString: (Int) -> String,
        methodLookup: (Int) -> String,
        fieldLookup: (Int) -> String,
        outCallees: MutableSet<String>,
        outStrings: MutableSet<String>
    ): String? {
        fun u16(offset: Int): Int {
            val pos = insnsStart + (pc + offset) * 2
            return if (pos >= 0 && pos + 2 <= buf.limit()) buf.getShort(pos).toInt() and 0xFFFF else 0
        }
        return when (op) {
            0x0E -> "return-void"
            0x0F, 0x10, 0x11 -> "return v${(unit0 ushr 8) and 0xFF}"
            0x1A -> {
                val sIdx = u16(1)
                val s = readString(sIdx).ifEmpty { "?" }.take(120)
                if (s != "?" && s.length >= 3) outStrings += s
                "const-string v${(unit0 ushr 8) and 0xFF}, \"$s\""
            }
            0x1B -> {
                val pos = insnsStart + (pc + 1) * 2
                val sIdx = if (pos >= 0 && pos + 4 <= buf.limit()) buf.getInt(pos) else 0
                val s = readString(sIdx).ifEmpty { "?" }.take(120)
                if (s != "?" && s.length >= 3) outStrings += s
                "const-string/jumbo \"$s\""
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
            0x6E, 0x6F, 0x70, 0x71, 0x72, 0x74, 0x75, 0x76, 0x77, 0x78 -> {
                val mIdx = u16(1)
                val resolved = methodLookup(mIdx)
                outCallees += resolved
                val name = when (op) {
                    0x6E, 0x74 -> "invoke-virtual"
                    0x6F, 0x75 -> "invoke-super"
                    0x70, 0x76 -> "invoke-direct"
                    0x71, 0x77 -> "invoke-static"
                    else -> "invoke-interface"
                }
                "$name $resolved"
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
        readUleb128(bytes, pos)
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
                if (sb.length < 180) sb.append(b.toChar())
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
