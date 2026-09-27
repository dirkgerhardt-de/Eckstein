/**
 * Poly1305 - One-time message authentication code (RFC 8439, section 2.5)
 *
 * Copyright (c) 2026 Dirk Gerhardt
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
package com.hekeki.eckstein.mac

import java.math.BigInteger

object Poly1305 {

    private const val KEY_SIZE = 32
    private const val TAG_SIZE = 16
    private const val BLOCK_SIZE = 16

    private val P = BigInteger.ONE.shiftLeft(130).subtract(BigInteger.valueOf(5))
    private val MOD_128 = BigInteger.ONE.shiftLeft(128)
    private val CLAMP_MASK = BigInteger("0ffffffc0ffffffc0ffffffc0fffffff", 16)

    fun authenticate(message: ByteArray, key: ByteArray): ByteArray {

        require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes, but was ${key.size}" }

        val r = littleEndianToNumber(key, 0, 16).and(CLAMP_MASK)
        val s = littleEndianToNumber(key, 16, 16)

        var acc = BigInteger.ZERO
        var offset = 0

        while (offset < message.size) {
            val blockLen = minOf(BLOCK_SIZE, message.size - offset)
            val block = littleEndianToNumber(message, offset, blockLen).or(BigInteger.ONE.shiftLeft(8 * blockLen))
            acc = r.multiply(acc.add(block)).mod(P)
            offset += blockLen
        }

        val tag = acc.add(s).mod(MOD_128)
        return numberToLittleEndian(tag, TAG_SIZE)
    }

    fun verify(mac: ByteArray, key: ByteArray, message: ByteArray): Boolean {

        val expected = authenticate(message, key)

        var diff = expected.size xor mac.size
        var i = 0
        while (i < expected.size && i < mac.size) {
            diff = diff or (expected[i].toInt() xor mac[i].toInt())
            i++
        }
        return diff == 0
    }

    private fun littleEndianToNumber(bytes: ByteArray, offset: Int, len: Int): BigInteger {
        var result = BigInteger.ZERO
        for (i in len - 1 downTo 0) {
            result = result.shiftLeft(8).or(BigInteger.valueOf((bytes[offset + i].toInt() and 0xFF).toLong()))
        }
        return result
    }

    private fun numberToLittleEndian(value: BigInteger, len: Int): ByteArray {
        val out = ByteArray(len)
        var v = value
        val mask = BigInteger.valueOf(0xFF)
        for (i in 0 until len) {
            out[i] = v.and(mask).toByte()
            v = v.shiftRight(8)
        }
        return out
    }
}