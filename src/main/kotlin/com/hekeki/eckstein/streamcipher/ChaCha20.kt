/**
 * ChaCha20 - Encryption and decryption with ChaCha20
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
package com.hekeki.eckstein.streamcipher

import kotlin.experimental.xor

object ChaCha20 {

    const val ROUNDS_20 = ArxCipherCore.ROUNDS_20
    const val ROUNDS_12 = ArxCipherCore.ROUNDS_12
    const val ROUNDS_8 = ArxCipherCore.ROUNDS_8
    const val KEY_SIZE_128 = ArxCipherCore.KEY_SIZE_128
    const val KEY_SIZE_256 = ArxCipherCore.KEY_SIZE_256
    const val NONCE_SIZE_ORIGINAL = ArxCipherCore.NONCE_SIZE_ORIGINAL
    const val NONCE_SIZE_IETF = 12
    const val BLOCK_SIZE = ArxCipherCore.BLOCK_SIZE

    private const val STATE_WORDS = ArxCipherCore.STATE_WORDS

    fun nonce(ietf: Boolean = true): ByteArray =
        ArxCipherCore.randomBytes(if (ietf) NONCE_SIZE_IETF else NONCE_SIZE_ORIGINAL)

    fun encrypt(
        key: ByteArray, nonce: ByteArray, plaintext: ByteArray,
        counter: Long = 0L, rounds: Int = ROUNDS_20
    ): ByteArray = crypt(key, nonce, plaintext, counter, rounds)

    fun decrypt(
        key: ByteArray, nonce: ByteArray, ciphertext: ByteArray,
        counter: Long = 0L, rounds: Int = ROUNDS_20
    ): ByteArray = crypt(key, nonce, ciphertext, counter, rounds)

    private fun crypt(
        key: ByteArray, nonce: ByteArray, data: ByteArray,
        counter: Long, rounds: Int
    ): ByteArray {
        ArxCipherCore.checkKeySize(key)
        checkNonce(nonce)
        ArxCipherCore.checkRounds(rounds)
        if (nonce.size == NONCE_SIZE_IETF) {
            require(counter in 0 until (1L shl 32)) {
                "Counter must fit in 32 bits for 12-byte (IETF) nonces, was $counter"
            }
        }

        val state = initState(key, nonce, counter)
        val work = IntArray(STATE_WORDS)
        val output = ByteArray(data.size)
        val block = ByteArray(BLOCK_SIZE)

        var pos = 0
        while (pos < data.size) {
            nextBlock(state, rounds, work, block)
            val take = minOf(BLOCK_SIZE, data.size - pos)
            for (i in 0 until take) {
                output[pos + i] = (data[pos + i] xor block[i]).toByte()
            }
            pos += take
            incrementCounter(state, nonce.size)
        }
        return output
    }

    private fun initState(key: ByteArray, nonce: ByteArray, counter: Long): IntArray {
        val k = ArxCipherCore.expandKeyWords(key)
        val c = ArxCipherCore.constantsFor(key)

        // State layout (row-major):
        // IETF (12-byte nonce):           original (8-byte nonce):
        //   c0 c1 c2 c3                     c0 c1 c2 c3
        //   k0 k1 k2 k3                     k0 k1 k2 k3
        //   k4 k5 k6 k7                     k4 k5 k6 k7
        //   b0 n0 n1 n2                     b0 b1 n0 n1
        val state = IntArray(STATE_WORDS)
        state[0] = c[0]
        state[1] = c[1]
        state[2] = c[2]
        state[3] = c[3]
        for (i in 0 until ArxCipherCore.KEY_WORDS) state[4 + i] = k[i]
        state[12] = counter.toInt()
        if (nonce.size == NONCE_SIZE_IETF) {
            state[13] = ArxCipherCore.leInt(nonce, 0)
            state[14] = ArxCipherCore.leInt(nonce, 4)
            state[15] = ArxCipherCore.leInt(nonce, 8)
        } else {
            state[13] = (counter ushr 32).toInt()
            state[14] = ArxCipherCore.leInt(nonce, 0)
            state[15] = ArxCipherCore.leInt(nonce, 4)
        }
        return state
    }

    private fun nextBlock(state: IntArray, rounds: Int, work: IntArray, block: ByteArray) {
        System.arraycopy(state, 0, work, 0, STATE_WORDS)

        repeat(rounds / 2) {
            // column round
            quarterRound(work, 0, 4, 8, 12)
            quarterRound(work, 1, 5, 9, 13)
            quarterRound(work, 2, 6, 10, 14)
            quarterRound(work, 3, 7, 11, 15)
            // diagonal round
            quarterRound(work, 0, 5, 10, 15)
            quarterRound(work, 1, 6, 11, 12)
            quarterRound(work, 2, 7, 8, 13)
            quarterRound(work, 3, 4, 9, 14)
        }

        // feed forward: output = rounds(state) + state, serialized little-endian
        for (i in 0 until STATE_WORDS) {
            ArxCipherCore.putLeInt(block, i * 4, work[i] + state[i])
        }
    }

    /**
     * Advances the block counter by one. state[12] is always the low (or only) counter word.
     *
     * For the original 8-byte nonce variant, state[13] is the high word of a 64-bit counter,
     * and an `Int` overflow of state[12] from 0xFFFFFFFF to 0x00000000 is the correct unsigned
     * carry into state[13]. For the 12-byte (IETF) nonce variant the counter is only 32 bits
     * wide per RFC 8439 and state[13..15] hold the nonce instead, so state[12] is left to wrap
     * silently (the caller already validated the initial counter fits in 32 bits).
     */
    private fun incrementCounter(state: IntArray, nonceSize: Int) {
        state[12]++
        if (nonceSize == NONCE_SIZE_ORIGINAL && state[12] == 0) state[13]++
    }

    /**
     * ChaCha20 quarter-round (4 ARX stages, rotations 16/12/8/7):
     * a += b; d ^= a; d <<<= 16;
     * c += d; b ^= c; b <<<= 12;
     * a += b; d ^= a; d <<<= 8;
     * c += d; b ^= c; b <<<= 7
     */
    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(16)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(12)
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(8)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(7)
    }

    private fun checkNonce(nonce: ByteArray) {
        require(nonce.size == NONCE_SIZE_IETF || nonce.size == NONCE_SIZE_ORIGINAL) {
            "Nonce must be 8 (original) or 12 (IETF) bytes, was ${nonce.size}"
        }
    }
}

