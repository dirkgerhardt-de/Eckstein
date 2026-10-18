/**
 * ArxCipherCore - shared building blocks for the Salsa20/ChaCha20 family of ARX stream ciphers
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
package com.hekeki.eckstein.streamcipher

import java.security.SecureRandom

internal object ArxCipherCore {

    const val ROUNDS_20 = 20
    const val ROUNDS_12 = 12
    const val ROUNDS_8 = 8
    const val KEY_SIZE_128 = 16
    const val KEY_SIZE_256 = 32
    const val NONCE_SIZE_ORIGINAL = 8
    const val BLOCK_SIZE = 64
    const val STATE_WORDS = 16
    const val KEY_WORDS = 8

    // "expand 32-byte k" - used for 256-bit keys
    val SIGMA = intArrayOf(
        0x61707865.toInt(), 0x3320646e.toInt(),
        0x79622d32.toInt(), 0x6b206574.toInt()
    )

    // "expand 16-byte k" - used instead of SIGMA when the key is only 128 bits
    val TAU = intArrayOf(
        0x61707865.toInt(), 0x3120646e.toInt(),
        0x79622d36.toInt(), 0x6b206574.toInt()
    )

    fun randomBytes(size: Int): ByteArray = ByteArray(size).also { SecureRandom().nextBytes(it) }

     fun expandKeyWords(key: ByteArray): IntArray {
        val k = IntArray(KEY_WORDS)
        val nk = key.size / 4
        for (i in 0 until nk) k[i] = leInt(key, i * 4)
        if (key.size == KEY_SIZE_128) {
            for (i in KEY_WORDS / 2 until KEY_WORDS) k[i] = k[i - KEY_WORDS / 2]
        }
        return k
    }

    fun constantsFor(key: ByteArray): IntArray = if (key.size == KEY_SIZE_128) TAU else SIGMA

    fun leInt(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or
                ((bytes[offset + 1].toInt() and 0xff) shl 8) or
                ((bytes[offset + 2].toInt() and 0xff) shl 16) or
                ((bytes[offset + 3].toInt() and 0xff) shl 24)

    fun putLeInt(bytes: ByteArray, offset: Int, value: Int) {
        bytes[offset] = (value and 0xff).toByte()
        bytes[offset + 1] = ((value ushr 8) and 0xff).toByte()
        bytes[offset + 2] = ((value ushr 16) and 0xff).toByte()
        bytes[offset + 3] = ((value ushr 24) and 0xff).toByte()
    }

    fun checkKeySize(key: ByteArray) {
        require(key.size == KEY_SIZE_128 || key.size == KEY_SIZE_256) {
            "Key must be 16 or 32 bytes, was ${key.size}"
        }
    }

    fun checkRounds(rounds: Int) {
        require(rounds in 8..ROUNDS_20 && rounds % 2 == 0) {
            "Rounds must be even and between 8 and 20, was $rounds"
        }
    }
}

