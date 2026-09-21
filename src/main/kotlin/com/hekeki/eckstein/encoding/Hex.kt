/**
 * Hex - Convert a string to hex and vice versa.
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
import java.nio.charset.StandardCharsets

object Hex {

    private val HEX_CHARS = "0123456789abcdef".toCharArray()

    @JvmOverloads
    fun encode(str: String, charset: Charset = StandardCharsets.UTF_8): String =
        encode(str.toByteArray(charset))

    fun encode(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xff
            sb.append(HEX_CHARS[v ushr 4])
            sb.append(HEX_CHARS[v and 0x0f])
        }
        return sb.toString()
    }

    @JvmOverloads
    fun decode(hex: String, charset: Charset = StandardCharsets.UTF_8): String =
        String(toByteArray(hex), charset)

    fun toByteArray(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "Hex string must have an even length, but was ${hex.length}: \"$hex\"" }
        val len = hex.length
        val data = ByteArray(len / 2)
        var i = 0
        while (i < len) {
            val hi = Character.digit(hex[i], 16)
            val lo = Character.digit(hex[i + 1], 16)
            require(hi != -1 && lo != -1) { "Invalid hex character at position $i in \"$hex\"" }
            data[i / 2] = ((hi shl 4) + lo).toByte()
            i += 2
        }
        return data
    }
}