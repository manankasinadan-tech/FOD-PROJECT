package com.example.fodtracer.core.disasm

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets

/**
 * Pure-Kotlin decoder for Android Binary XML (AXML) and compiled resource tables (resources.arsc).
 * Extracts exact typed FOD/UDFPS/Biometric/HBM configuration values from RRO overlays,
 * SystemUI, and framework-res without executing or installing anything.
 */
object BinaryXmlAndArscDecoder {

    private const val CHUNK_STRING_POOL = 0x0001
    private const val CHUNK_TABLE = 0x0002
    private const val CHUNK_XML = 0x0003
    private const val CHUNK_XML_RESOURCE_MAP = 0x0180
    private const val CHUNK_XML_START_ELEMENT = 0x0102
    private const val CHUNK_XML_END_ELEMENT = 0x0103

    private const val CHUNK_TABLE_PACKAGE = 0x0200
    private const val CHUNK_TABLE_TYPE = 0x0201
    private const val CHUNK_TABLE_TYPE_SPEC = 0x0202

    private val FOD_KEY_FILTERS = listOf(
        "udfps", "fod", "fingerprint", "biometric", "hbm", "lhbm",
        "doze", "aod", "dim", "brightness", "display", "sensor",
        "touch", "overlay", "targetpackage", "priority", "isstatic"
    )

    data class ResourcePoolResult(
        val strings: List<String>,
        val nextOffset: Int
    )

    fun decodeBinaryXml(bytes: ByteArray): String? {
        if (bytes.size < 16) return null
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val rootType = buf.getShort(0).toInt() and 0xFFFF
        if (rootType != CHUNK_XML) return null

        val rootHeaderSize = buf.getShort(2).toInt() and 0xFFFF
        val totalSize = buf.getInt(4).coerceIn(0, bytes.size)
        var pos = rootHeaderSize.coerceAtLeast(8)

        var strings: List<String> = emptyList()
        val out = StringBuilder()
        var depth = 0
        var elementsDecoded = 0

        while (pos + 8 <= totalSize && elementsDecoded < 600) {
            val type = buf.getShort(pos).toInt() and 0xFFFF
            val chunkSize = buf.getInt(pos + 4)
            if (chunkSize < 8 || pos.toLong() + chunkSize.toLong() > totalSize.toLong()) break

            when (type) {
                CHUNK_STRING_POOL -> {
                    strings = parseStringPool(bytes, buf, pos, chunkSize)
                }
                CHUNK_XML_RESOURCE_MAP -> {
                    // Resource ID map chunk; skipped cleanly
                }
                CHUNK_XML_START_ELEMENT -> {
                    if (pos + 36 <= totalSize) {
                        val nameIdx = buf.getInt(pos + 20)
                        val attrStart = buf.getShort(pos + 24).toInt() and 0xFFFF
                        val attrSize = (buf.getShort(pos + 26).toInt() and 0xFFFF).coerceAtLeast(20)
                        val attrCount = (buf.getShort(pos + 28).toInt() and 0xFFFF).coerceIn(0, 64)
                        val tagName = strings.getOrElse(nameIdx) { "tag_$nameIdx" }

                        val indent = "  ".repeat(depth.coerceIn(0, 8))
                        out.append("$indent<$tagName")
                        val attrsBaseLong = pos.toLong() + 16L + attrStart.toLong()
                        val chunkEndLong = pos.toLong() + chunkSize.toLong()
                        if (attrsBaseLong in pos.toLong()..chunkEndLong) {
                            for (a in 0 until attrCount) {
                                val aOffLong = attrsBaseLong + a.toLong() * attrSize.toLong()
                                if (aOffLong < 0L || aOffLong + 20L > chunkEndLong) break
                                val aOff = aOffLong.toInt()
                                val attrNameIdx = buf.getInt(aOff + 4)
                                val rawValueIdx = buf.getInt(aOff + 8)
                                val valueType = bytes[aOff + 15].toInt() and 0xFF
                                val valueData = buf.getInt(aOff + 16)
                                val attrName = strings.getOrElse(attrNameIdx) { "attr_$attrNameIdx" }
                                val renderedVal = if (rawValueIdx in strings.indices && valueType == 0x03) {
                                    strings[rawValueIdx]
                                } else {
                                    formatTypedValue(valueType, valueData, strings)
                                }
                                out.append(" $attrName=\"$renderedVal\"")
                            }
                        }
                        out.appendLine(">")
                        depth++
                        elementsDecoded++
                    }
                }
                CHUNK_XML_END_ELEMENT -> {
                    if (pos + 24 <= totalSize) {
                        depth = (depth - 1).coerceAtLeast(0)
                        val nameIdx = buf.getInt(pos + 20)
                        val tagName = strings.getOrElse(nameIdx) { "tag_$nameIdx" }
                        val indent = "  ".repeat(depth.coerceIn(0, 8))
                        out.appendLine("$indent</$tagName>")
                    }
                }
            }
            pos += chunkSize
        }

        return out.toString().takeIf { it.isNotBlank() }
    }

    /**
     * Parses resources.arsc and extracts exact typed FOD/UDFPS/Biometric/HBM/Overlay entries.
     */
    fun extractArscEntries(bytes: ByteArray, filterFodOnly: Boolean = true): List<String> = runCatching {
        if (bytes.size < 24) return@runCatching emptyList()
        val buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        val rootType = buf.getShort(0).toInt() and 0xFFFF
        if (rootType != CHUNK_TABLE) return@runCatching emptyList()

        val rootHeaderSize = buf.getShort(2).toInt() and 0xFFFF
        val totalSize = buf.getInt(4).coerceIn(0, bytes.size)
        var pos = rootHeaderSize.coerceAtLeast(12)

        var globalStrings: List<String> = emptyList()
        val results = linkedSetOf<String>()

        while (pos + 8 <= totalSize && results.size < 250) {
            val type = buf.getShort(pos).toInt() and 0xFFFF
            val headerSize = buf.getShort(pos + 2).toInt() and 0xFFFF
            val chunkSize = buf.getInt(pos + 4)
            if (chunkSize < 8 || pos.toLong() + chunkSize.toLong() > totalSize.toLong()) break

            when (type) {
                CHUNK_STRING_POOL -> {
                    if (globalStrings.isEmpty()) {
                        globalStrings = parseStringPool(bytes, buf, pos, chunkSize)
                    }
                }
                CHUNK_TABLE_PACKAGE -> {
                    parsePackageChunk(
                        bytes = bytes,
                        buf = buf,
                        pkgStart = pos,
                        pkgHeaderSize = headerSize,
                        pkgSize = chunkSize,
                        globalStrings = globalStrings,
                        filterFodOnly = filterFodOnly,
                        out = results
                    )
                }
            }
            pos += chunkSize
        }
        results.toList()
    }.getOrDefault(emptyList())

    private fun parsePackageChunk(
        bytes: ByteArray,
        buf: ByteBuffer,
        pkgStart: Int,
        pkgHeaderSize: Int,
        pkgSize: Int,
        globalStrings: List<String>,
        filterFodOnly: Boolean,
        out: MutableSet<String>
    ) {
        val pkgEnd = (pkgStart.toLong() + pkgSize.toLong()).coerceAtMost(bytes.size.toLong()).toInt()
        if (pkgStart + 280 > pkgEnd) return
        val typeStringsRel = buf.getInt(pkgStart + 268).toLong() and 0xFFFFFFFFL
        val keyStringsRel = buf.getInt(pkgStart + 276).toLong() and 0xFFFFFFFFL

        val tsPosLong = pkgStart.toLong() + typeStringsRel
        val typeStrings = if (typeStringsRel > 0L && tsPosLong + 8L < pkgEnd.toLong()) {
            val tsPos = tsPosLong.toInt()
            val tsSize = buf.getInt(tsPos + 4)
            if (tsSize >= 8 && tsPosLong + tsSize.toLong() <= pkgEnd.toLong()) {
                parseStringPool(bytes, buf, tsPos, tsSize)
            } else emptyList()
        } else emptyList()

        val ksPosLong = pkgStart.toLong() + keyStringsRel
        val keyStrings = if (keyStringsRel > 0L && ksPosLong + 8L < pkgEnd.toLong()) {
            val ksPos = ksPosLong.toInt()
            val ksSize = buf.getInt(ksPos + 4)
            if (ksSize >= 8 && ksPosLong + ksSize.toLong() <= pkgEnd.toLong()) {
                parseStringPool(bytes, buf, ksPos, ksSize)
            } else emptyList()
        } else emptyList()

        var pos = pkgStart + pkgHeaderSize.coerceAtLeast(288)
        while (pos + 8 <= pkgEnd && out.size < 250) {
            val chunkType = buf.getShort(pos).toInt() and 0xFFFF
            val chunkHeaderSize = buf.getShort(pos + 2).toInt() and 0xFFFF
            val chunkSize = buf.getInt(pos + 4)
            if (chunkSize < 8 || pos.toLong() + chunkSize.toLong() > pkgEnd.toLong()) break

            if (chunkType == CHUNK_TABLE_TYPE && pos + 20 <= pkgEnd) {
                parseTypeChunk(
                    bytes = bytes,
                    buf = buf,
                    typePos = pos,
                    headerSize = chunkHeaderSize,
                    chunkSize = chunkSize,
                    typeStrings = typeStrings,
                    keyStrings = keyStrings,
                    globalStrings = globalStrings,
                    filterFodOnly = filterFodOnly,
                    out = out
                )
            }
            pos += chunkSize
        }
    }

    private fun parseTypeChunk(
        bytes: ByteArray,
        buf: ByteBuffer,
        typePos: Int,
        headerSize: Int,
        chunkSize: Int,
        typeStrings: List<String>,
        keyStrings: List<String>,
        globalStrings: List<String>,
        filterFodOnly: Boolean,
        out: MutableSet<String>
    ) {
        val chunkEnd = (typePos.toLong() + chunkSize.toLong()).coerceAtMost(bytes.size.toLong()).toInt()
        val typeId = bytes[typePos + 8].toInt() and 0xFF
        val flags = bytes[typePos + 9].toInt() and 0xFF
        val entryCount = buf.getInt(typePos + 12).coerceIn(0, 30_000)
        val entriesStartRel = buf.getInt(typePos + 16).toLong() and 0xFFFFFFFFL
        val entriesBaseLong = typePos.toLong() + entriesStartRel
        if (entriesStartRel < headerSize.toLong() || entriesBaseLong > chunkEnd.toLong()) return
        val entriesBase = entriesBaseLong.toInt()

        val typeName = typeStrings.getOrElse(typeId - 1) { "type_$typeId" }
        val isSparse = (flags and 0x01) != 0
        val offsetsStart = typePos + headerSize

        for (i in 0 until entryCount) {
            if (out.size >= 250) break
            val entryOffset: Long
            if (isSparse) {
                val pairOff = offsetsStart + i * 4
                if (pairOff < typePos || pairOff + 4 > entriesBase) break
                val rawOff16 = buf.getShort(pairOff + 2).toInt() and 0xFFFF
                if (rawOff16 == 0xFFFF) continue
                entryOffset = rawOff16.toLong() * 4L
            } else {
                val offPos = offsetsStart + i * 4
                if (offPos < typePos || offPos + 4 > entriesBase) break
                val rawOff = buf.getInt(offPos)
                if (rawOff == -1) continue
                entryOffset = rawOff.toLong() and 0xFFFFFFFFL
            }

            val ePosLong = entriesBase.toLong() + entryOffset
            if (ePosLong < entriesBase.toLong() || ePosLong + 8L > chunkEnd.toLong()) continue
            val ePos = ePosLong.toInt()
            val entrySize = buf.getShort(ePos).toInt() and 0xFFFF
            if (entrySize < 8) continue
            val entryFlags = buf.getShort(ePos + 2).toInt() and 0xFFFF
            val keyIdx = buf.getInt(ePos + 4)
            val keyName = keyStrings.getOrElse(keyIdx) { continue }

            val matchesFilter = !filterFodOnly ||
                FOD_KEY_FILTERS.any { keyName.contains(it, ignoreCase = true) }
            if (!matchesFilter) continue

            val isComplex = (entryFlags and 0x0001) != 0
            if (!isComplex) {
                val valOffLong = ePos.toLong() + entrySize.toLong()
                if (valOffLong >= ePos.toLong() && valOffLong + 8L <= chunkEnd.toLong()) {
                    val valOff = valOffLong.toInt()
                    val valType = bytes[valOff + 3].toInt() and 0xFF
                    val valData = buf.getInt(valOff + 4)
                    val formatted = formatTypedValue(valType, valData, globalStrings)
                    out += "$typeName/$keyName = $formatted"
                }
            } else {
                if (ePos + 16 <= chunkEnd) {
                    val mapCount = buf.getInt(ePos + 12).coerceIn(0, 32)
                    var mapPosLong = ePos.toLong() + entrySize.toLong()
                    val items = mutableListOf<String>()
                    repeat(mapCount) {
                        if (mapPosLong >= ePos.toLong() && mapPosLong + 12L <= chunkEnd.toLong()) {
                            val mapPos = mapPosLong.toInt()
                            val valType = bytes[mapPos + 7].toInt() and 0xFF
                            val valData = buf.getInt(mapPos + 8)
                            items += formatTypedValue(valType, valData, globalStrings)
                            mapPosLong += 12L
                        }
                    }
                    out += "$typeName/$keyName = [${items.joinToString(", ")}]"
                }
            }
        }
    }

    private fun parseStringPool(
        bytes: ByteArray,
        buf: ByteBuffer,
        poolPos: Int,
        poolSize: Int
    ): List<String> {
        val poolEnd = (poolPos.toLong() + poolSize.toLong()).coerceAtMost(bytes.size.toLong()).toInt()
        if (poolPos < 0 || poolPos + 28 > poolEnd) return emptyList()

        val stringCount = buf.getInt(poolPos + 8).coerceIn(0, 60_000)
        val flags = buf.getInt(poolPos + 16)
        val isUtf8 = (flags and (1 shl 8)) != 0
        val stringsStartRel = buf.getInt(poolPos + 20).toLong() and 0xFFFFFFFFL
        val offsetsBase = poolPos + 28
        val dataBaseLong = poolPos.toLong() + stringsStartRel
        if (stringsStartRel < 28L || dataBaseLong >= poolEnd.toLong()) return emptyList()
        val dataBase = dataBaseLong.toInt()

        val result = ArrayList<String>(stringCount)
        for (i in 0 until stringCount) {
            val idxPos = offsetsBase + i * 4
            if (idxPos < poolPos || idxPos + 4 > dataBase) {
                result += ""
                continue
            }
            val relStrOff = buf.getInt(idxPos).toLong() and 0xFFFFFFFFL
            val strOffLong = dataBase.toLong() + relStrOff
            if (strOffLong !in dataBase.toLong() until poolEnd.toLong()) {
                result += ""
                continue
            }
            val strOff = strOffLong.toInt()
            val str = if (isUtf8) {
                readLengthPrefixedUtf8(bytes, strOff, poolEnd)
            } else {
                readLengthPrefixedUtf16(bytes, buf, strOff, poolEnd)
            }
            result += str
        }
        return result
    }

    private fun readLengthPrefixedUtf8(bytes: ByteArray, start: Int, limit: Int): String {
        var pos = start
        if (pos >= limit) return ""
        // Skip utf16 char len (1 or 2 bytes)
        val u16 = bytes[pos++].toInt() and 0xFF
        if ((u16 and 0x80) != 0 && pos < limit) pos++
        if (pos >= limit) return ""
        // Read utf8 byte len (1 or 2 bytes)
        var u8Len = bytes[pos++].toInt() and 0xFF
        if ((u8Len and 0x80) != 0 && pos < limit) {
            val low = bytes[pos++].toInt() and 0xFF
            u8Len = ((u8Len and 0x7F) shl 8) or low
        }
        val safeLen = u8Len.coerceIn(0, (limit - pos).coerceAtLeast(0)).coerceAtMost(240)
        return String(bytes, pos, safeLen, StandardCharsets.UTF_8)
    }

    private fun readLengthPrefixedUtf16(bytes: ByteArray, buf: ByteBuffer, start: Int, limit: Int): String {
        var pos = start
        if (pos + 2 > limit) return ""
        var charLen = buf.getShort(pos).toInt() and 0xFFFF
        pos += 2
        if ((charLen and 0x8000) != 0 && pos + 2 <= limit) {
            val low = buf.getShort(pos).toInt() and 0xFFFF
            charLen = ((charLen and 0x7FFF) shl 16) or low
            pos += 2
        }
        val byteLen = (charLen * 2).coerceIn(0, (limit - pos).coerceAtLeast(0)).coerceAtMost(480)
        return String(bytes, pos, byteLen, StandardCharsets.UTF_16LE)
    }

    private fun formatTypedValue(type: Int, data: Int, strings: List<String>): String {
        return when (type) {
            0x01 -> "@0x${data.toUInt().toString(16)}" // TYPE_REFERENCE
            0x03 -> strings.getOrElse(data) { "str@$data" } // TYPE_STRING
            0x04 -> java.lang.Float.intBitsToFloat(data).toString() // TYPE_FLOAT
            0x05 -> decodeDimension(data) // TYPE_DIMENSION
            0x10 -> data.toString() // TYPE_INT_DEC
            0x11 -> "0x${data.toUInt().toString(16)}" // TYPE_INT_HEX
            0x12 -> (data != 0).toString() // TYPE_INT_BOOLEAN
            in 0x1C..0x1F -> "#${data.toUInt().toString(16).padStart(8, '0')}" // COLORS
            else -> "type($type)=0x${data.toUInt().toString(16)}"
        }
    }

    private fun decodeDimension(data: Int): String {
        val mantissa = data shr 8
        val radix = (data ushr 4) and 0x3
        val unit = data and 0xF
        val scale = when (radix) {
            0 -> 1f
            1 -> 1f / 128f
            2 -> 1f / 32768f
            else -> 1f / 8388608f
        }
        val value = mantissa * scale
        val unitLabel = when (unit) {
            0 -> "px"
            1 -> "dp"
            2 -> "sp"
            3 -> "pt"
            4 -> "in"
            5 -> "mm"
            else -> "u$unit"
        }
        return "$value$unitLabel"
    }
}
