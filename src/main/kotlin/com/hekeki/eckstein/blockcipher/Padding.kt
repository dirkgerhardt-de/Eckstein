/**
 * Padding - Class to pad messages
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
package com.hekeki.eckstein.blockcipher

object Padding {

    enum class SCHEME {
        NONE,
        PKCS5,
        PKCS7
    }

    fun pkcs7Padding(bytes: ByteArray): ByteArray {
        return pkcsPadding(bytes, 16)
    }

    fun pkcs5Padding(bytes: ByteArray): ByteArray {
        return pkcsPadding(bytes, 8)
    }

    fun pkcs7Unpadding(bytes: ByteArray): ByteArray {
        return pkcsUnpadding(bytes)
    }

    fun pkcs5Unpadding(bytes: ByteArray): ByteArray {
        return pkcsUnpadding(bytes)
    }

    private fun pkcsPadding(bytes: ByteArray, size: Int): ByteArray {
        val padding = size - bytes.size % size
        val result = bytes.copyOf(bytes.size + padding)
        for (i in 0 until padding) {
            result[bytes.size + i] = padding.toByte()
        }
        return result
    }

    private fun pkcsUnpadding(b: ByteArray): ByteArray {
        val unpadding = b[b.size - 1].toInt() and 0xff
        val result = ByteArray(b.size - unpadding)
        for (i in result.indices) {
            result[i] = b[i]
        }
        return result
    }
}