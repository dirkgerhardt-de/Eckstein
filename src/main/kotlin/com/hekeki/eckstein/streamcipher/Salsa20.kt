/**
 * Salsa20 - Encryption and decryption with Salsa20
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

object Salsa20 {

    const val ROUNDS_20 = ArxCipherCore.ROUNDS_20
    const val ROUNDS_12 = ArxCipherCore.ROUNDS_12
    const val ROUNDS_8 = ArxCipherCore.ROUNDS_8
    const val KEY_SIZE_128 = ArxCipherCore.KEY_SIZE_128
    const val KEY_SIZE_256 = ArxCipherCore.KEY_SIZE_256
    const val NONCE_SIZE = ArxCipherCore.NONCE_SIZE_ORIGINAL
    const val BLOCK_SIZE = ArxCipherCore.BLOCK_SIZE

    private const val STATE_WORDS = ArxCipherCore.STATE_WORDS

    fun nonce(): ByteArray = ArxCipherCore.randomBytes(NONCE_SIZE)

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
            incrementCounter(state)
        }
        return output
    }

    private fun initState(key: ByteArray, nonce: ByteArray, counter: Long): IntArray {
        val k = ArxCipherCore.expandKeyWords(key)
        val c = ArxCipherCore.constantsFor(key)

        // State layout (constants on the diagonal, key/nonce/counter around it):
        //   c0 k0 k1 k2
        //   k3 c1 n0 n1
        //   b0 b1 c2 k4
        //   k5 k6 k7 c3
        val state = IntArray(STATE_WORDS)
        state[0] = c[0]
        state[1] = k[0]
        state[2] = k[1]
        state[3] = k[2]
        state[4] = k[3]
        state[5] = c[1]
        state[6] = ArxCipherCore.leInt(nonce, 0)
        state[7] = ArxCipherCore.leInt(nonce, 4)
        state[8] = counter.toInt()
        state[9] = (counter ushr 32).toInt()
        state[10] = c[2]
        state[11] = k[4]
        state[12] = k[5]
        state[13] = k[6]
        state[14] = k[7]
        state[15] = c[3]
        return state
    }

    private fun nextBlock(state: IntArray, rounds: Int, work: IntArray, block: ByteArray) {
        System.arraycopy(state, 0, work, 0, STATE_WORDS)

        repeat(rounds / 2) {
            // column round
            quarterRound(work, 0, 4, 8, 12)
            quarterRound(work, 5, 9, 13, 1)
            quarterRound(work, 10, 14, 2, 6)
            quarterRound(work, 15, 3, 7, 11)
            // row round
            quarterRound(work, 0, 1, 2, 3)
            quarterRound(work, 5, 6, 7, 4)
            quarterRound(work, 10, 11, 8, 9)
            quarterRound(work, 15, 12, 13, 14)
        }

        // feed forward: output = rounds(state) + state, serialized little-endian
        for (i in 0 until STATE_WORDS) {
            ArxCipherCore.putLeInt(block, i * 4, work[i] + state[i])
        }
    }

    /**
     * Advances the 64-bit block counter (state[8] = low word, state[9] = high word) by one.
     *
     * Both words are treated as unsigned 32-bit values, so a `Int` overflow of state[8]
     * from 0xFFFFFFFF to 0x00000000 is the correct carry into state[9]. Once state[9] itself
     * wraps from 0xFFFFFFFF to 0x00000000, the full 64-bit counter silently wraps around to 0
     * (2^64 * 64 bytes = 1 EiB of keystream, which is unreachable in practice).
     */
    private fun incrementCounter(state: IntArray) {
        state[8]++
        if (state[8] == 0) state[9]++
    }

    /**
     * quarter-round:
     * y1 ^= (y0 + y3) <<< 7;  y2 ^= (y1 + y0) <<< 9;
     * y3 ^= (y2 + y1) <<< 13; y0 ^= (y3 + y2) <<< 18
     */
    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[b] = x[b] xor (x[a] + x[d]).rotateLeft(7)
        x[c] = x[c] xor (x[b] + x[a]).rotateLeft(9)
        x[d] = x[d] xor (x[c] + x[b]).rotateLeft(13)
        x[a] = x[a] xor (x[d] + x[c]).rotateLeft(18)
    }

    private fun checkNonce(nonce: ByteArray) {
        require(nonce.size == NONCE_SIZE) {
            "Nonce must be 8 bytes, was ${nonce.size}"
        }
    }
}

