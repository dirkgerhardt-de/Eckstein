/**
 * SHA3 - Generate SHA3 hash
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
package com.hekeki.eckstein.hash

import com.hekeki.eckstein.encoding.Hex


object SHA3 {

    fun sha224(message: ByteArray) = keccak(SHA3.VARIANT.SHA224, message)
    fun sha224(message: String) = Hex.encode(sha224(message.toByteArray()))

    fun sha256(message: ByteArray) = keccak(SHA3.VARIANT.SHA256, message)
    fun sha256(message: String) = Hex.encode(sha256(message.toByteArray()))

    fun sha384(message: ByteArray) = keccak(SHA3.VARIANT.SHA384, message)
    fun sha384(message: String) = Hex.encode(sha384(message.toByteArray()))

    fun sha512(message: ByteArray) = keccak(SHA3.VARIANT.SHA512, message)
    fun sha512(message: String) = Hex.encode(sha512(message.toByteArray()))

    private fun keccak(variant: VARIANT, msgBytes: ByteArray): ByteArray {

        val chunks = msgBytes.size / variant.blockSize() + 1

        // Padding
        val padded = padding(variant, msgBytes, chunks)

        // Initialization
        val s = LongArray(25)

        // Absorbing phase
        for (i in 0 until chunks) {
            for (j in 0 until variant.blockSize() step 8) {
                s[j.ushr(3)] = s[j.ushr(3)] xor longify(padded, i * variant.blockSize() + j)
            }
            keccakf(s)
        }

        // Squeezing phase
        // no need for additional block permutations in the squeezing phase, because in sha3
        // result is greater than output length, so leading bits are the desired hash
        val result = ByteArray(variant.outputSize() * 8)
        for (i in 0 until variant.outputSize() step 8) {
            getBytes(s[i.ushr(3)], result, i)
        }

        return result.copyOf(variant.outputSize())
    }

    private fun padding(variant: VARIANT, msgBytes: ByteArray, chunks: Int): ByteArray {

        val padded = msgBytes.copyOf(chunks * variant.blockSize())

        if (msgBytes.size + 1 == padded.size) {
            padded[msgBytes.size] = 0x86.toByte()
        } else {
            padded[msgBytes.size] = 0x06.toByte()
            padded[padded.size - 1] = 0x80.toByte()
        }
        return padded
    }

    private fun longify(bytes: ByteArray, offset: Int): Long {
        return ((bytes[offset].toInt() and 0xFF).toLong()
                or ((bytes[offset + 1].toInt() and 0xFF).toLong() shl 8)
                or ((bytes[offset + 2].toInt() and 0xFF).toLong() shl 16)
                or ((bytes[offset + 3].toInt() and 0xFF).toLong() shl 24)
                or ((bytes[offset + 4].toInt() and 0xFF).toLong() shl 32)
                or ((bytes[offset + 5].toInt() and 0xFF).toLong() shl 40)
                or ((bytes[offset + 6].toInt() and 0xFF).toLong() shl 48)
                or ((bytes[offset + 7].toInt() and 0xFF).toLong() shl 56))
    }

    private fun keccakf(s: LongArray) {
        for (n in 0..23) {
            round(s, n)
        }
    }

    private fun round(s: LongArray, n: Int) {

        val b = LongArray(25)
        val c = LongArray(5)
        val d = LongArray(5)

        // Theta step
        for (x in 0..4) {
            c[x] = s[idx(x, 0)] xor s[idx(x, 1)] xor s[idx(x, 2)] xor s[idx(x, 3)] xor s[idx(x, 4)]
        }
        for (x in 0..4) {
            d[x] = c[idx(x - 1)] xor rotate(c[idx(x + 1)], 1)

        }
        for (x in 0..4) {
            for (y in 0..4) {
                s[idx(x, y)] = s[idx(x, y)] xor d[x]
            }
        }
        // Rho and Pi steps
        for (x in 0..4) {
            for (y in 0..4) {
                val i = idx(x, y)
                b[idx(y, x * 2 + 3 * y)] = rotate(s[i], R[i])
            }
        }
        // Chi step
        for (x in 0..4) {
            for (y in 0..4) {
                val i = idx(x, y)
                s[i] = b[i] xor (b[idx(x + 1, y)].inv() and b[idx(x + 2, y)])
            }
        }
        // Iota step
        s[0] = s[0] xor RC[n]
    }

    private fun idx(x: Int, y: Int): Int {
        // for (x,y) such that x+5*y < r/w
        return idx(x) + 5 * idx(y)
    }

    private fun idx(x: Int): Int {
        return if (x < 0) idx(x + 5) else x % 5
    }

    private fun rotate(value: Long, dist: Int): Long {
        return value shl dist or value.ushr(-dist)
    }

    private fun getBytes(n: Long, out: ByteArray, off: Int) {
        out[off] = n.toByte()
        out[off + 1] = n.ushr(8).toByte()
        out[off + 2] = n.ushr(16).toByte()
        out[off + 3] = n.ushr(24).toByte()
        out[off + 4] = n.ushr(32).toByte()
        out[off + 5] = n.ushr(40).toByte()
        out[off + 6] = n.ushr(48).toByte()
        out[off + 7] = n.ushr(56).toByte()
    }

    private val RC = longArrayOf(
        0x0000000000000001L, 0x0000000000008082L, -0x7fffffffffff7f76L, -0x7fffffff7fff8000L,
        0x000000000000808bL, 0x0000000080000001L, -0x7fffffff7fff7f7fL, -0x7fffffffffff7ff7L,
        0x000000000000008aL, 0x0000000000000088L, 0x0000000080008009L, 0x000000008000000aL,
        0x000000008000808bL, -0x7fffffffffffff75L, -0x7fffffffffff7f77L, -0x7fffffffffff7ffdL,
        -0x7fffffffffff7ffeL, -0x7fffffffffffff80L, 0x000000000000800aL, -0x7fffffff7ffffff6L,
        -0x7fffffff7fff7f7fL, -0x7fffffffffff7f80L, 0x0000000080000001L, -0x7fffffff7fff7ff8L
    )

    private val R = intArrayOf(0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14)

    private enum class VARIANT {
        SHA224 {
            override fun outputSize(): Int {
                return 28
            }

            override fun blockSize(): Int {
                return 144
            }
        },
        SHA256 {
            override fun outputSize(): Int {
                return 32
            }

            override fun blockSize(): Int {
                return 136
            }
        },
        SHA384 {
            override fun outputSize(): Int {
                return 48
            }

            override fun blockSize(): Int {
                return 104
            }
        },
        SHA512 {
            override fun outputSize(): Int {
                return 64
            }

            override fun blockSize(): Int {
                return 72
            }
        };

        abstract fun outputSize(): Int
        abstract fun blockSize(): Int
    }
}