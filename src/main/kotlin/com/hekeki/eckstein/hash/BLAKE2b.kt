/**
 * BLAKE2b - Generate BLAKE2b hash (RFC 7693)
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
package com.hekeki.eckstein.hash

import com.hekeki.eckstein.encoding.Hex

object BLAKE2b {

    private const val BLOCK_BYTES = 128
    private const val MAX_DIGEST_BYTES = 64
    private const val MAX_KEY_BYTES = 64

    fun hash(message: ByteArray): ByteArray = compute(message, ByteArray(0), MAX_DIGEST_BYTES)
    fun hash(message: String): String = Hex.encode(hash(message.toByteArray()))

    fun hash(message: ByteArray, digestLength: Int): ByteArray = compute(message, ByteArray(0), digestLength)
    fun hash(message: String, digestLength: Int): String = Hex.encode(hash(message.toByteArray(), digestLength))

    fun mac(message: String, key: String, digestLength: Int): String = Hex.encode(mac(message.toByteArray(), key.toByteArray(), digestLength))
    fun mac(message: ByteArray, key: ByteArray, digestLength: Int): ByteArray {
        require(key.isNotEmpty()) { "mac() requires a non-empty key" }
        return compute(message, key, digestLength)
    }

    private fun compute(message: ByteArray, key: ByteArray, digestLength: Int): ByteArray {
        require(digestLength in 1..MAX_DIGEST_BYTES) {
            "digestLength must be between 1 and $MAX_DIGEST_BYTES bytes"
        }
        require(key.size <= MAX_KEY_BYTES) {
            "key must not be longer than $MAX_KEY_BYTES bytes"
        }

        val h = IV.copyOf()
        h[0] = h[0] xor (0x01010000L xor (key.size.toLong() shl 8) xor digestLength.toLong())

        var counterLow = 0L
        var counterHigh = 0L

        val padded = if (key.isEmpty()) {
            message
        } else {
            val prefixed = ByteArray(BLOCK_BYTES + message.size)
            key.copyInto(prefixed)
            message.copyInto(prefixed, BLOCK_BYTES)
            prefixed
        }

        val v = LongArray(16)
        val m = LongArray(16)

        var offset = 0
        while (padded.size - offset > BLOCK_BYTES) {
            val before = counterLow
            counterLow += BLOCK_BYTES
            if (counterLow.toULong() < before.toULong()) counterHigh++
            compress(h, padded, offset, counterLow, counterHigh, false, v, m)
            offset += BLOCK_BYTES
        }

        val remaining = padded.size - offset
        val before = counterLow
        counterLow += remaining
        if (counterLow.toULong() < before.toULong()) counterHigh++
        val lastBlock = ByteArray(BLOCK_BYTES)
        if (remaining > 0) {
            padded.copyInto(lastBlock, 0, offset, offset + remaining)
        }
        compress(h, lastBlock, 0, counterLow, counterHigh, true, v, m)

        val out = ByteArray(digestLength)
        for (i in out.indices) {
            out[i] = (h[i ushr 3] ushr (8 * (i and 7))).toByte()
        }
        return out
    }

    private fun compress(
        h: LongArray,
        block: ByteArray,
        blockOffset: Int,
        counterLow: Long,
        counterHigh: Long,
        last: Boolean,
        v: LongArray,
        m: LongArray
    ) {

        for (i in 0 until 16) {
            m[i] = littleEndianLong(block, blockOffset + i * 8)
        }

        for (i in 0 until 8) {
            v[i] = h[i]
            v[i + 8] = IV[i]
        }
        v[12] = v[12] xor counterLow
        v[13] = v[13] xor counterHigh
        if (last) {
            v[14] = v[14].inv()
        }

        for (round in 0 until 12) {
            val s = SIGMA[round]
            mix(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            mix(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            mix(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            mix(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            mix(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            mix(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            mix(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            mix(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for (i in 0 until 8) {
            h[i] = h[i] xor v[i] xor v[i + 8]
        }
    }

    private fun mix(v: LongArray, a: Int, b: Int, c: Int, d: Int, x: Long, y: Long) {
        v[a] = v[a] + v[b] + x
        v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 32)
        v[c] = v[c] + v[d]
        v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 24)
        v[a] = v[a] + v[b] + y
        v[d] = java.lang.Long.rotateRight(v[d] xor v[a], 16)
        v[c] = v[c] + v[d]
        v[b] = java.lang.Long.rotateRight(v[b] xor v[c], 63)
    }

    private fun littleEndianLong(bytes: ByteArray, offset: Int): Long {
        var value = 0L
        for (i in 0 until 8) {
            value = value or ((bytes[offset + i].toLong() and 0xFF) shl (8 * i))
        }
        return value
    }

    private val IV = longArrayOf(
        0x6A09E667F3BCC908L, -0x4498517a7b3558c5L, 0x3C6EF372FE94F82BL, -0x5ab00ac5a0e2c90fL,
        0x510E527FADE682D1L, -0x64fa9773d4c193e1L, 0x1F83D9ABFB41BD6BL, 0x5BE0CD19137E2179L
    )

    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3)
    )
}