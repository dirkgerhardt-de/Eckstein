/**
 * Base64 - Convert text or bytes to base64 encoded string and vice versa.
 *
 * Copyright (c) 2018 - 2026 Dirk Gerhardt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
package com.hekeki.eckstein.encoding

import java.nio.charset.Charset

object Base64 {

    private const val CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

    fun encode(src: ByteArray): String = encode(src, false, Charset.defaultCharset())

    fun encode(src: ByteArray, wrap: Boolean): String = encode(src, wrap, Charset.defaultCharset())

    fun encode(src: ByteArray, charset: Charset): String = encode(src, false, charset)

    fun encode(src: ByteArray, wrap: Boolean, charset: Charset): String = asString(base64encode(src, wrap), charset)

    fun encode(src: String): String = encode(src.toByteArray(Charset.defaultCharset()), false, Charset.defaultCharset())

    fun encode(src: String, wrap: Boolean): String = encode(src.toByteArray(Charset.defaultCharset()), wrap, Charset.defaultCharset())

    fun encode(src: String, charset: Charset): String = encode(src.toByteArray(charset), false, charset)

    fun encode(src: String, wrap: Boolean, charset: Charset): String = encode(src.toByteArray(charset), wrap, charset)

    fun decode(src: ByteArray): ByteArray = base64decode(src)

    fun decode(src: ByteArray, charset: Charset): String = asString(base64decode(src), charset)

    fun decode(src: String): ByteArray = decode(src.toByteArray(Charsets.ISO_8859_1))

    fun decode(src: String, charset: Charset): String = decode(src.toByteArray(Charsets.ISO_8859_1), charset)

    private fun base64encode(bytes: ByteArray, wrap: Boolean): ByteArray {

        val size = (bytes.size + 2) / 3 * 4
        val numberOfNewlines = if (wrap && size > 0) ((size / 4 - 1) / 19) * 2 else 0
        var numberOfPaddings = if (bytes.size % 3 == 0) 0 else 3 - (bytes.size % 3)
        val srcp = bytes.copyOf(bytes.size + numberOfPaddings)
        val result = ByteArray(size + numberOfNewlines)
        var si = 0
        var ri = 0
        while (si < srcp.size) {
            if (wrap && si > 0 && (si / 3 * 4) % 76 == 0) {
                result[ri++] = 13
                result[ri++] = 10
            }
            val n = (srcp[si++].toInt() and 0xff shl 16) or (srcp[si++].toInt() and 0xff shl 8) or (srcp[si++].toInt() and 0xff)
            result[ri++] = CHARS[n shr 18 and 63].code.toByte()
            result[ri++] = CHARS[n shr 12 and 63].code.toByte()
            result[ri++] = CHARS[n shr 6 and 63].code.toByte()
            result[ri++] = CHARS[n and 63].code.toByte()
        }

        while (numberOfPaddings > 0) {
            result[result.size - numberOfPaddings] = 61
            numberOfPaddings--
        }

        return result
    }

    private fun base64decode(src: ByteArray): ByteArray {

        val tempBytes = mutableListOf<Byte>()

        src.filter { CHARS.contains(it.toInt().toChar()) }
            .forEach {
                when {
                    it == 43.toByte() -> tempBytes.add(62)
                    it == 47.toByte() -> tempBytes.add(63)
                    it < 58 -> tempBytes.add((it + 4).toByte())
                    it < 91 -> tempBytes.add((it - 65).toByte())
                    it < 123 -> tempBytes.add((it - 71).toByte())
                }
            }

        val byteDest = ByteArray(tempBytes.size * 3 / 4)

        var si = 0
        var di = 0
        while (si < tempBytes.size && di < byteDest.size / 3 * 3) {
            byteDest[di++] = (tempBytes[si++].toInt() shl 2 and 0xfc or (tempBytes[si].toInt().ushr(4) and 0x03)).toByte()
            byteDest[di++] = (tempBytes[si++].toInt() shl 4 and 0xf0 or (tempBytes[si].toInt().ushr(2) and 0x0f)).toByte()
            byteDest[di++] = (tempBytes[si++].toInt() shl 6 and 0xc0 or (tempBytes[si++].toInt() and 0x3F)).toByte()
        }

        if (si < tempBytes.size - 2) {
            byteDest[di++] = (tempBytes[si++].toInt() shl 2 and 0xfc or (tempBytes[si].toInt().ushr(4) and 0x03)).toByte()
            byteDest[di] = (tempBytes[si++].toInt() shl 4 and 0xf0 or (tempBytes[si].toInt().ushr(2) and 0x0f)).toByte()
        } else if (si < tempBytes.size - 1) {
            byteDest[di] = (tempBytes[si++].toInt() shl 2 and 0xfc or (tempBytes[si].toInt().ushr(4) and 0x03)).toByte()
        }

        return byteDest
    }

    private fun asString(encoded: ByteArray, charset: Charset): String = String(encoded, charset)
}