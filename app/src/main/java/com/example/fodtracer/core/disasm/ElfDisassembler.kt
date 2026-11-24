package com.example.fodtracer.core.disasm

import com.example.fodtracer.domain.models.ArtifactKind
import com.example.fodtracer.domain.models.DisassembledArtifact
import com.example.fodtracer.domain.models.EpistemicLevel
import com.example.fodtracer.domain.models.PartitionOrigin
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/**
 * Pure-Kotlin ELF32/ELF64 parser + AArch64 instruction disassembler with PLT/GOT resolution.
 * Extracts DT_NEEDED dependencies, dynsym/symtab FOD symbols, .plt/@got imported calls,
 * .rodata strings, ARM64 disassembly listings, and function-to-syscall/string cross-references.
 */
object ElfDisassembler {

    private val FOD_SYMBOL_KEYWORDS = listOf(
        "finger", "udfps", "fod", "hbm", "lhbm", "dim", "backlight", "brightness",
        "goodix", "gf_", "fpc", "silead", "focal", "egis", "qbt", "jiiov", "chipone",
        "biometric", "enroll", "acquire", "auth", "touch", "panel", "drm", "ioctl",
        "onfinger", "illuminate", "display", "composer", "layer", "vendor", "hal"
    )

    private val FOD_STRING_KEYWORDS = listOf(
        "/sys/", "/dev/", "goodix", "fpc", "silead", "focal", "egis", "qbt",
        "hbm", "lhbm", "udfps", "fod", "dim", "fingerprint", "biometric",
        "android.hardware.biometrics", "persist.", "vendor.", "ioctl", "drm", "panel"
    )

    fun analyze(
        id: String,
        path: String,
        partition: PartitionOrigin,
        bytes: ByteArray
    ): Pair<DisassembledArtifact, String>? {
        if (bytes.size < 64) return null
        if (bytes[0] != 0x7F.toByte() || bytes[1] != 'E'.code.toByte() ||
            bytes[2] != 'L'.code.toByte() || bytes[3] != 'F'.code.toByte()
        ) {
            return null
        }

        val eiClass = bytes[4].toInt() and 0xFF
        val eiData = bytes[5].toInt() and 0xFF
        val order = if (eiData == 2) ByteOrder.BIG_ENDIAN else ByteOrder.LITTLE_ENDIAN
        val buf = ByteBuffer.wrap(bytes).order(order)

        val is64 = eiClass == 2
        val eType = buf.getShort(16).toInt() and 0xFFFF
        val eMachine = buf.getShort(18).toInt() and 0xFFFF
        val archName = when (eMachine) {
            183 -> "AArch64 (ARM64)"
            40 -> "ARM32"
            62 -> "x86_64"
            3 -> "x86"
            else -> "EM_$eMachine"
        }
        val kind = if (eType == 3 && !path.contains("/bin/")) ArtifactKind.ELF_SHARED_LIB else ArtifactKind.ELF_BINARY

        val shOff = if (is64) buf.getLong(40) else (buf.getInt(32).toLong() and 0xFFFFFFFFL)
        val shEntSize = if (is64) (buf.getShort(58).toInt() and 0xFFFF) else (buf.getShort(46).toInt() and 0xFFFF)
        val shNum = if (is64) (buf.getShort(60).toInt() and 0xFFFF) else (buf.getShort(48).toInt() and 0xFFFF)
        val shStrNdx = if (is64) (buf.getShort(62).toInt() and 0xFFFF) else (buf.getShort(50).toInt() and 0xFFFF)

        val sections = parseSections(buf, bytes.size, is64, shOff, shEntSize, shNum, shStrNdx)
        val dynStrSec = sections.firstOrNull { it.name == ".dynstr" }
        val strTabSec = sections.firstOrNull { it.name == ".strtab" }
        val dynSec = sections.firstOrNull { it.type == 6 /* SHT_DYNAMIC */ || it.name == ".dynamic" }
        val rodataSections = sections.filter { it.name.startsWith(".rodata") }
        val textSec = sections.firstOrNull { it.name == ".text" }
        val pltSec = sections.firstOrNull { it.name == ".plt" }

        val neededLibs = extractNeededLibs(buf, bytes, is64, dynSec, dynStrSec)
        val dynSymbols = sections.firstOrNull { it.name == ".dynsym" || it.type == 11 }
            ?.let { parseSymTab(buf, bytes, is64, it, dynStrSec) }
            .orEmpty()
        val staticSymbols = sections.firstOrNull { it.name == ".symtab" || it.type == 2 }
            ?.let { parseSymTab(buf, bytes, is64, it, strTabSec) }
            .orEmpty()
        val symbols = (dynSymbols + staticSymbols)

        val relevantSymbols = symbols
            .filter { sym -> sym.name.isNotBlank() && FOD_SYMBOL_KEYWORDS.any { sym.name.contains(it, true) } }
            .distinctBy { "${it.name}@${it.value}" }
            .take(240)

        val rodataStrings = if (rodataSections.isNotEmpty()) {
            rodataSections.flatMap { extractInterestingStrings(bytes, it, 160) }.distinct().take(200)
        } else {
            extractInterestingStrings(bytes, null, 160)
        }

        val rodataMap = HashMap<Long, String>()
        rodataSections.forEach { sec -> rodataMap.putAll(indexRodataStrings(bytes, sec)) }

        val symbolByAddr = HashMap<Long, String>()
        symbols.filter { it.value > 0L && it.name.isNotBlank() }.forEach { sym ->
            symbolByAddr[sym.value] = sym.name
        }

        // Resolve .plt stubs via .rela.plt/.rel.plt GOT slots -> "<sym@plt>"
        val gotSlotToSymbol = extractRelocationGotMap(buf, bytes.size, is64, sections, dynSymbols)
        if (eMachine == 183 && pltSec != null && gotSlotToSymbol.isNotEmpty()) {
            symbolByAddr.putAll(resolveAarch64PltStubs(buf, bytes.size, pltSec, gotSlotToSymbol))
        }

        val xrefs = mutableListOf<String>()
        val disasmText = buildString {
            appendLine("=== FodTracer ELF Analysis & Disassembly ===")
            appendLine("File: $path")
            appendLine("Arch: $archName | Class: ${if (is64) "ELF64" else "ELF32"} | Bytes parsed: ${bytes.size}")
            if (neededLibs.isNotEmpty()) {
                appendLine("\n[DT_NEEDED Dependencies (${neededLibs.size})]")
                neededLibs.forEach { appendLine("  -> $it") }
            }
            if (gotSlotToSymbol.isNotEmpty()) {
                val importantPlts = gotSlotToSymbol.values
                    .filter { sym ->
                        FOD_SYMBOL_KEYWORDS.any { sym.contains(it, true) } ||
                            sym in setOf("ioctl", "open", "openat", "write", "read", "close", "mmap", "dlopen", "dlsym", "property_get", "__android_log_print")
                    }
                    .distinct()
                    .take(40)
                if (importantPlts.isNotEmpty()) {
                    appendLine("\n[Resolved PLT/GOT Imports (${importantPlts.size})]")
                    importantPlts.forEach { appendLine("  PLT -> $it") }
                }
            }
            if (rodataStrings.isNotEmpty()) {
                appendLine("\n[.rodata / Binary Strings (${rodataStrings.size})]")
                rodataStrings.forEach { appendLine("  \"$it\"") }
            }
            if (relevantSymbols.isNotEmpty()) {
                appendLine("\n[FOD / Biometric / HBM Symbols (${relevantSymbols.size})]")
                relevantSymbols.forEach { sym ->
                    val kindTag = if (sym.shndx == 0) "IMP" else "DEF"
                    appendLine("  [$kindTag] 0x${sym.value.toString(16).padStart(8, '0')} (size=${sym.size}) ${sym.name}")
                }
            }

            if (eMachine == 183 && textSec != null && textSec.offset in 0 until bytes.size.toLong()) {
                val targetFns = relevantSymbols
                    .filter { it.shndx != 0 && it.value >= textSec.addr && it.value < textSec.addr + textSec.size }
                    .distinctBy { it.value }
                    .take(48)

                if (targetFns.isNotEmpty()) {
                    appendLine("\n[AArch64 Disassembly (.text) — ${targetFns.size} functions]")
                    for (fn in targetFns) {
                        if (length > 100_000) break
                        val relOffset = fn.value - textSec.addr
                        val filePosLong = textSec.offset + relOffset
                        if (filePosLong < 0L || filePosLong + 4L > bytes.size.toLong()) continue
                        val filePos = filePosLong.toInt()
                        val maxBytesToDecode = if (fn.size in 4..1024) fn.size.toInt() else 256
                        val instrCount = (maxBytesToDecode / 4).coerceIn(4, 160)
                        appendLine("\n<${fn.name}> @ 0x${fn.value.toString(16)}:")
                        val adrpPages = HashMap<Int, Long>()
                        val fnCalls = linkedSetOf<String>()
                        val fnStrings = linkedSetOf<String>()

                        for (i in 0 until instrCount) {
                            val offLong = filePosLong + i * 4L
                            if (offLong < 0L || offLong + 4L > bytes.size.toLong()) break
                            val off = offLong.toInt()
                            val word = buf.getInt(off)
                            val pc = fn.value + i * 4L
                            val decoded = decodeAarch64(word, pc, adrpPages, rodataMap, symbolByAddr, fnCalls, fnStrings)
                            appendLine("  0x${pc.toString(16).padStart(8, '0')}:  ${word.toUInt().toString(16).padStart(8, '0')}   $decoded")
                            if (decoded == "ret") break
                        }

                        if (fnCalls.isNotEmpty() || fnStrings.isNotEmpty()) {
                            val parts = buildList {
                                if (fnCalls.isNotEmpty()) add("calls=[${fnCalls.joinToString(", ")}]")
                                if (fnStrings.isNotEmpty()) add("refs=[${fnStrings.joinToString(", ") { "\"$it\"" }}]")
                            }
                            xrefs += "${fn.name} -> ${parts.joinToString(" | ")}"
                        }
                    }
                }
            }

            if (xrefs.isNotEmpty()) {
                appendLine("\n[Cross-References (Calls -> Targets/Strings)]")
                xrefs.forEach { appendLine("  $it") }
            }
        }

        val snippet = disasmText.lines().take(75).joinToString("\n")
        val rawFileName = "disassembly/${path.trim('/').replace('/', '_')}.asm.txt"

        val artifact = DisassembledArtifact(
            id = id,
            name = path.substringAfterLast('/'),
            path = path,
            partition = partition,
            kind = kind,
            architecture = archName,
            neededLibraries = neededLibs,
            keySymbols = relevantSymbols.map {
                val tag = if (it.shndx == 0) "IMP" else "0x${it.value.toString(16)}"
                "$tag ${it.name}"
            },
            extractedStrings = rodataStrings,
            disassemblySnippet = snippet,
            epistemicLevel = EpistemicLevel.PROVED,
            rawFileName = rawFileName,
            crossReferences = xrefs
        )
        return artifact to disasmText
    }

    private data class ElfSection(
        val name: String,
        val type: Int,
        val addr: Long,
        val offset: Long,
        val size: Long,
        val entSize: Long
    )

    private data class ElfSymbol(
        val name: String,
        val value: Long,
        val size: Long,
        val shndx: Int
    )

    private fun extractRelocationGotMap(
        buf: ByteBuffer,
        fileLen: Int,
        is64: Boolean,
        sections: List<ElfSection>,
        dynSymbols: List<ElfSymbol>
    ): Map<Long, String> {
        if (dynSymbols.isEmpty()) return emptyMap()
        val gotMap = HashMap<Long, String>()
        val relSections = sections.filter {
            it.name in setOf(".rela.plt", ".rel.plt", ".rela.dyn", ".rel.dyn") || it.type == 4 || it.type == 9
        }
        for (sec in relSections) {
            val isRela = sec.type == 4 || sec.name.startsWith(".rela")
            val entSize = if (sec.entSize > 0) sec.entSize.toInt() else {
                if (is64) (if (isRela) 24 else 16) else (if (isRela) 12 else 8)
            }
            val startLong = sec.offset
            val endLong = (sec.offset + sec.size).coerceAtMost(fileLen.toLong())
            if (startLong < 0L || startLong >= endLong || startLong > Int.MAX_VALUE) continue
            val start = startLong.toInt()
            val end = endLong.toInt()

            var pos = start
            while (pos + entSize <= end && gotMap.size < 4000) {
                val rOffset: Long
                val symIdx: Int
                if (is64) {
                    rOffset = buf.getLong(pos)
                    val rInfo = buf.getLong(pos + 8)
                    symIdx = (rInfo ushr 32).toInt()
                } else {
                    rOffset = buf.getInt(pos).toLong() and 0xFFFFFFFFL
                    val rInfo = buf.getInt(pos + 4)
                    symIdx = rInfo ushr 8
                }
                if (rOffset > 0L && symIdx in dynSymbols.indices) {
                    val symName = dynSymbols[symIdx].name
                    if (symName.isNotBlank()) {
                        gotMap[rOffset] = symName
                    }
                }
                pos += entSize
            }
        }
        return gotMap
    }

    /**
     * Scans AArch64 .plt stubs (ADRP X16/X17 + ADD/LDR -> GOT slot) to map PLT entry virtual addresses
     * directly to imported library symbols (`name@plt`).
     */
    private fun resolveAarch64PltStubs(
        buf: ByteBuffer,
        fileLen: Int,
        pltSec: ElfSection,
        gotSlotToSymbol: Map<Long, String>
    ): Map<Long, String> {
        val result = HashMap<Long, String>()
        val start = pltSec.offset.toInt()
        val end = (pltSec.offset + pltSec.size).coerceAtMost(fileLen.toLong()).toInt()
        if (start < 0 || start + 16 > end) return result

        val pages = LongArray(32) { Long.MIN_VALUE }
        val pageSetPc = LongArray(32) { Long.MIN_VALUE }

        var pos = start
        while (pos + 4 <= end) {
            val insn = buf.getInt(pos)
            val pc = pltSec.addr + (pos - start)
            val rd = insn and 0x1F
            val rn = (insn ushr 5) and 0x1F

            // ADRP Xd, page
            if ((insn and 0x9F000000.toInt()) == 0x90000000.toInt()) {
                val immlo = (insn ushr 29) and 0x3
                val immhi = (insn ushr 5) and 0x7FFFF
                val imm = signExtend((immhi shl 2) or immlo, 21).toLong() shl 12
                pages[rd] = (pc and -4096L) + imm
                pageSetPc[rd] = pc
            } else if ((insn and 0xFFC00000.toInt()) == 0xF9400000.toInt()) {
                // LDR Xd, [Xn, #imm12*8]
                val page = pages[rn]
                if (page != Long.MIN_VALUE) {
                    val imm12 = ((insn ushr 10) and 0xFFF).toLong() * 8L
                    val gotAddr = page + imm12
                    val sym = gotSlotToSymbol[gotAddr]
                    if (sym != null && pageSetPc[rn] >= pltSec.addr) {
                        result[pageSetPc[rn]] = "$sym@plt"
                    }
                }
            }
            pos += 4
        }
        return result
    }

    private fun parseSections(
        buf: ByteBuffer,
        fileLen: Int,
        is64: Boolean,
        shOff: Long,
        shEntSize: Int,
        shNum: Int,
        shStrNdx: Int
    ): List<ElfSection> {
        if (shOff <= 0L || shNum <= 0 || shNum > 256 || shEntSize <= 0) return emptyList()
        if (shOff + shNum.toLong() * shEntSize > fileLen.toLong()) return emptyList()

        val raw = ArrayList<ElfSection>(shNum)
        val nameOffsets = IntArray(shNum)
        for (i in 0 until shNum) {
            val base = (shOff + i.toLong() * shEntSize).toInt()
            if (is64 && base + 64 <= fileLen) {
                nameOffsets[i] = buf.getInt(base)
                val type = buf.getInt(base + 4)
                val addr = buf.getLong(base + 16)
                val offset = buf.getLong(base + 24)
                val size = buf.getLong(base + 32)
                val entSize = buf.getLong(base + 56)
                raw += ElfSection("", type, addr, offset, size, entSize)
            } else if (!is64 && base + 40 <= fileLen) {
                nameOffsets[i] = buf.getInt(base)
                val type = buf.getInt(base + 4)
                val addr = buf.getInt(base + 12).toLong() and 0xFFFFFFFFL
                val offset = buf.getInt(base + 16).toLong() and 0xFFFFFFFFL
                val size = buf.getInt(base + 20).toLong() and 0xFFFFFFFFL
                val entSize = buf.getInt(base + 36).toLong() and 0xFFFFFFFFL
                raw += ElfSection("", type, addr, offset, size, entSize)
            }
        }

        if (shStrNdx in raw.indices) {
            val strSec = raw[shStrNdx]
            val arr = buf.array()
            return raw.mapIndexed { idx, sec ->
                val name = readCString(arr, strSec.offset.toInt(), strSec.size.toInt(), nameOffsets[idx])
                sec.copy(name = name)
            }
        }
        return raw
    }

    private fun extractNeededLibs(
        buf: ByteBuffer,
        bytes: ByteArray,
        is64: Boolean,
        dynSec: ElfSection?,
        dynStrSec: ElfSection?
    ): List<String> {
        if (dynSec == null || dynStrSec == null) return emptyList()
        val entSize = if (dynSec.entSize > 0) dynSec.entSize.toInt() else if (is64) 16 else 8
        val start = dynSec.offset.toInt()
        val end = (dynSec.offset + dynSec.size).coerceAtMost(bytes.size.toLong()).toInt()
        if (start < 0 || start >= end) return emptyList()

        val libs = mutableListOf<String>()
        var pos = start
        while (pos + entSize <= end && libs.size < 96) {
            val tag = if (is64) buf.getLong(pos) else buf.getInt(pos).toLong()
            val value = if (is64) buf.getLong(pos + 8) else (buf.getInt(pos + 4).toLong() and 0xFFFFFFFFL)
            if (tag == 0L) break
            if (tag == 1L /* DT_NEEDED */) {
                val lib = readCString(bytes, dynStrSec.offset.toInt(), dynStrSec.size.toInt(), value.toInt())
                if (lib.isNotBlank()) libs += lib
            }
            pos += entSize
        }
        return libs.distinct()
    }

    private fun parseSymTab(
        buf: ByteBuffer,
        bytes: ByteArray,
        is64: Boolean,
        symSec: ElfSection,
        strSec: ElfSection?
    ): List<ElfSymbol> {
        if (strSec == null) return emptyList()
        val entSize = if (symSec.entSize > 0) symSec.entSize.toInt() else if (is64) 24 else 16
        val start = symSec.offset.toInt()
        val end = (symSec.offset + symSec.size).coerceAtMost(bytes.size.toLong()).toInt()
        if (start < 0 || start >= end) return emptyList()

        val list = mutableListOf<ElfSymbol>()
        var pos = start
        while (pos + entSize <= end && list.size < 12_000) {
            val nameIdx = buf.getInt(pos)
            val shndx: Int
            val value: Long
            val size: Long
            if (is64) {
                shndx = buf.getShort(pos + 6).toInt() and 0xFFFF
                value = buf.getLong(pos + 8)
                size = buf.getLong(pos + 16)
            } else {
                value = buf.getInt(pos + 4).toLong() and 0xFFFFFFFFL
                size = buf.getInt(pos + 8).toLong() and 0xFFFFFFFFL
                shndx = buf.getShort(pos + 14).toInt() and 0xFFFF
            }
            val name = readCString(bytes, strSec.offset.toInt(), strSec.size.toInt(), nameIdx)
            list += ElfSymbol(name, value, size, shndx)
            pos += entSize
        }
        return list
    }

    private fun extractInterestingStrings(
        bytes: ByteArray,
        section: ElfSection?,
        maxStrings: Int
    ): List<String> {
        val start = section?.offset?.toInt()?.coerceIn(0, bytes.size) ?: 0
        val end = if (section != null) {
            (section.offset + section.size).coerceAtMost(bytes.size.toLong()).toInt()
        } else {
            bytes.size
        }
        val results = linkedSetOf<String>()
        val sb = StringBuilder()
        for (i in start until end) {
            val b = bytes[i].toInt() and 0xFF
            if (b in 0x20..0x7E) {
                if (sb.length < 200) sb.append(b.toChar())
            } else {
                if (sb.length >= 5) {
                    val s = sb.toString()
                    if (FOD_STRING_KEYWORDS.any { s.contains(it, ignoreCase = true) }) {
                        results += s
                        if (results.size >= maxStrings) break
                    }
                }
                sb.clear()
            }
        }
        return results.toList()
    }

    private fun indexRodataStrings(bytes: ByteArray, rodata: ElfSection?): Map<Long, String> {
        if (rodata == null || rodata.offset < 0L || rodata.size <= 0L) return emptyMap()
        val start = rodata.offset.coerceIn(0L, bytes.size.toLong()).toInt()
        val end = (rodata.offset + rodata.size).coerceAtMost(bytes.size.toLong()).toInt()
        val map = HashMap<Long, String>()
        var strStart = -1
        for (i in start until end) {
            val b = bytes[i].toInt() and 0xFF
            if (b in 0x20..0x7E) {
                if (strStart == -1) strStart = i
            } else {
                if (b == 0 && strStart != -1 && i - strStart in 3..180) {
                    val s = String(bytes, strStart, i - strStart, StandardCharsets.US_ASCII)
                    val vaddr = rodata.addr + (strStart - rodata.offset)
                    map[vaddr] = s
                    if (map.size >= 20_000) break
                }
                strStart = -1
            }
        }
        return map
    }

    private fun readCString(bytes: ByteArray, secOff: Int, secSize: Int, relOff: Int): String {
        if (secOff < 0 || relOff < 0 || secSize <= 0) return ""
        val start = secOff + relOff
        val limit = (secOff + secSize).coerceAtMost(bytes.size)
        if (start >= limit) return ""
        var end = start
        while (end < limit && bytes[end] != 0.toByte() && end - start < 220) {
            end++
        }
        return String(bytes, start, end - start, StandardCharsets.UTF_8)
    }

    private fun decodeAarch64(
        insn: Int,
        pc: Long,
        adrpPages: MutableMap<Int, Long>,
        rodataStrings: Map<Long, String>,
        symbolsByAddr: Map<Long, String>,
        outCalls: MutableSet<String>,
        outStrings: MutableSet<String>
    ): String {
        val u = insn.toUInt()
        if (insn == 0xD65F03C0.toInt()) return "ret"
        if (insn == 0xD503201F.toInt()) return "nop"

        val rd = insn and 0x1F
        val rn = (insn ushr 5) and 0x1F
        val rm = (insn ushr 16) and 0x1F

        // B / BL: [31]=op, [30:26]=00101
        if ((insn and 0x7C000000) == 0x14000000) {
            val isLink = (insn ushr 31) != 0
            val imm26 = signExtend(insn and 0x03FFFFFF, 26)
            val target = pc + (imm26.toLong() shl 2)
            val symName = symbolsByAddr[target]
            if (symName != null && isLink) {
                outCalls += symName
            }
            val sym = symName?.let { " <$it>" } ?: ""
            return "${if (isLink) "bl" else "b"} 0x${target.toString(16)}$sym"
        }

        if ((insn and 0xFFFFFC1F.toInt()) == 0xD63F0000.toInt()) return "blr x$rn"
        if ((insn and 0xFFFFFC1F.toInt()) == 0xD61F0000.toInt()) return "br x$rn"

        if ((insn and 0xFFE0001F.toInt()) == 0xD4000001.toInt()) {
            val imm16 = (insn ushr 5) and 0xFFFF
            outCalls += "svc #0x${imm16.toString(16)}"
            return "svc #0x${imm16.toString(16)}"
        }

        // ADRP Xd, label
        if ((insn and 0x9F000000.toInt()) == 0x90000000.toInt()) {
            val immlo = (insn ushr 29) and 0x3
            val immhi = (insn ushr 5) and 0x7FFFF
            val imm = signExtend((immhi shl 2) or immlo, 21).toLong() shl 12
            val page = (pc and -4096L) + imm
            adrpPages[rd] = page
            return "adrp x$rd, 0x${page.toString(16)}"
        }

        // ADD / SUB immediate
        if ((insn and 0x3F000000) == 0x11000000) {
            val is64 = (insn ushr 31) != 0
            val isSub = ((insn ushr 30) and 1) != 0
            val isS = ((insn ushr 29) and 1) != 0
            val sh = ((insn ushr 22) and 1) * 12
            val imm12 = ((insn ushr 10) and 0xFFF).toLong() shl sh
            val prefix = if (is64) "x" else "w"
            val mnem = when {
                isSub && isS && rd == 31 -> return "cmp $prefix$rn, #0x${imm12.toString(16)}"
                isSub && isS -> "subs"
                isSub -> "sub"
                isS -> "adds"
                else -> "add"
            }
            val resolvedComment = if (!isSub && !isS && is64) {
                adrpPages[rn]?.let { page ->
                    val target = page + imm12
                    val str = rodataStrings[target]
                    val sym = symbolsByAddr[target]
                    when {
                        str != null -> {
                            outStrings += str
                            " ; \"$str\""
                        }
                        sym != null -> {
                            outCalls += sym
                            " ; <$sym>"
                        }
                        else -> ""
                    }
                } ?: ""
            } else ""
            return "$mnem $prefix$rd, $prefix$rn, #0x${imm12.toString(16)}$resolvedComment"
        }

        // MOVZ / MOVK / MOVN
        if ((insn and 0x1F800000) == 0x12800000) {
            val is64 = (insn ushr 31) != 0
            val opc = (insn ushr 29) and 0x3
            val hw = ((insn ushr 21) and 0x3) * 16
            val imm16 = (insn ushr 5) and 0xFFFF
            val reg = if (is64) "x$rd" else "w$rd"
            val mnem = when (opc) {
                0 -> "movn"
                2 -> "movz"
                3 -> "movk"
                else -> "mov_op"
            }
            return "$mnem $reg, #0x${imm16.toString(16)}" + if (hw > 0) ", lsl #$hw" else ""
        }

        // CBZ / CBNZ
        if ((insn and 0x7E000000) == 0x34000000) {
            val is64 = (insn ushr 31) != 0
            val isNz = ((insn ushr 24) and 1) != 0
            val imm19 = signExtend((insn ushr 5) and 0x7FFFF, 19).toLong() shl 2
            val target = pc + imm19
            val reg = if (is64) "x$rd" else "w$rd"
            return "${if (isNz) "cbnz" else "cbz"} $reg, 0x${target.toString(16)}"
        }

        // B.cond
        if ((insn and 0xFF000010.toInt()) == 0x54000000) {
            val cond = insn and 0xF
            val imm19 = signExtend((insn ushr 5) and 0x7FFFF, 19).toLong() shl 2
            val target = pc + imm19
            val condName = COND_CODES.getOrElse(cond) { "c$cond" }
            return "b.$condName 0x${target.toString(16)}"
        }

        // STP / LDP
        val top10 = (u.toInt() ushr 22) and 0x3FF
        if (top10 in listOf(0x2A4, 0x2A5, 0x2A6, 0x2A7, 0x2A0, 0x2A1, 0x2A2, 0x2A3)) {
            val isLoad = (top10 and 1) != 0
            val rt2 = (insn ushr 10) and 0x1F
            val imm7 = signExtend((insn ushr 15) and 0x7F, 7) * 8
            val mnem = if (isLoad) "ldp" else "stp"
            return "$mnem x$rd, x$rt2, [x$rn, #$imm7]"
        }

        // LDR / STR unsigned offset
        if ((insn and 0x3FC00000) == 0x39400000 || (insn and 0x3FC00000) == 0x39000000) {
            val size = (insn ushr 30) and 0x3
            val isLoad = ((insn ushr 22) and 1) != 0
            if (size >= 2) {
                val scale = if (size == 3) 8 else 4
                val imm12 = ((insn ushr 10) and 0xFFF) * scale
                val reg = if (size == 3) "x$rd" else "w$rd"
                val base = if (rn == 31) "sp" else "x$rn"
                val resolved = if (isLoad && size == 3) {
                    adrpPages[rn]?.let { page ->
                        gotOrSymHint(page + imm12, symbolsByAddr, outCalls)
                    } ?: ""
                } else ""
                return "${if (isLoad) "ldr" else "str"} $reg, [$base, #$imm12]$resolved"
            }
        }

        // MOV Xd, Xm
        if ((insn and 0xFFE0FFE0.toInt()) == 0xAA0003E0.toInt()) {
            return "mov x$rd, x$rm"
        }

        return "insn 0x${u.toString(16).padStart(8, '0')}"
    }

    private fun gotOrSymHint(
        addr: Long,
        symbolsByAddr: Map<Long, String>,
        outCalls: MutableSet<String>
    ): String {
        val sym = symbolsByAddr[addr] ?: return ""
        outCalls += sym
        return " ; <$sym>"
    }

    private fun signExtend(value: Int, bits: Int): Int {
        val shift = 32 - bits
        return (value shl shift) shr shift
    }

    private val COND_CODES = listOf(
        "eq", "ne", "cs", "cc", "mi", "pl", "vs", "vc",
        "hi", "ls", "ge", "lt", "gt", "le", "al", "nv"
    )
}
