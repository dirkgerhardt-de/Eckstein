/**
 * XSalsa20 - Extended-nonce variant of Salsa20 (192-bit / 24-byte nonce)
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

object XSalsa20 {

    const val ROUNDS_20 = ArxCipherCore.ROUNDS_20
    const val ROUNDS_12 = ArxCipherCore.ROUNDS_12
    const val ROUNDS_8 = ArxCipherCore.ROUNDS_8
    const val KEY_SIZE_256 = ArxCipherCore.KEY_SIZE_256
    const val NONCE_SIZE = 24    // 192-bit nonce (16 bytes for HSalsa20 + 8 bytes for Salsa20)
    const val SUBKEY_SIZE = 32   // 256-bit subkey

    private const val HSALSA20_NONCE_SIZE = 16
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
        checkKeySize(key)
        checkNonce(nonce)
        ArxCipherCore.checkRounds(rounds)

        val subkey = hSalsa20(key, nonce.copyOfRange(0, HSALSA20_NONCE_SIZE), rounds)
        val salsaNonce = nonce.copyOfRange(HSALSA20_NONCE_SIZE, NONCE_SIZE)
        try {
            return Salsa20.encrypt(subkey, salsaNonce, data, counter, rounds)
        } finally {
            subkey.fill(0)
        }
    }

    /**
     * HSalsa20 - subkey derivation for XSalsa20.
     *
     * Uses the Salsa20 core with the 16-byte input placed in state words 6..9 and
     * returns words 0, 5, 10, 15, 6, 7, 8, 9 of the result (no feed-forward).
     */
    fun hSalsa20(key: ByteArray, nonce: ByteArray, rounds: Int = ROUNDS_20): ByteArray {
        checkKeySize(key)
        require(nonce.size == HSALSA20_NONCE_SIZE) {
            "HSalsa20 requires 128-bit nonce, was ${nonce.size} bytes"
        }
        ArxCipherCore.checkRounds(rounds)

        val k = ArxCipherCore.expandKeyWords(key)
        val c = ArxCipherCore.SIGMA

        val x = IntArray(STATE_WORDS)
        x[0] = c[0]
        x[1] = k[0]
        x[2] = k[1]
        x[3] = k[2]
        x[4] = k[3]
        x[5] = c[1]
        x[6] = ArxCipherCore.leInt(nonce, 0)
        x[7] = ArxCipherCore.leInt(nonce, 4)
        x[8] = ArxCipherCore.leInt(nonce, 8)
        x[9] = ArxCipherCore.leInt(nonce, 12)
        x[10] = c[2]
        x[11] = k[4]
        x[12] = k[5]
        x[13] = k[6]
        x[14] = k[7]
        x[15] = c[3]

        repeat(rounds / 2) {
            // column round
            quarterRound(x, 0, 4, 8, 12)
            quarterRound(x, 5, 9, 13, 1)
            quarterRound(x, 10, 14, 2, 6)
            quarterRound(x, 15, 3, 7, 11)
            // row round
            quarterRound(x, 0, 1, 2, 3)
            quarterRound(x, 5, 6, 7, 4)
            quarterRound(x, 10, 11, 8, 9)
            quarterRound(x, 15, 12, 13, 14)
        }

        val subkey = ByteArray(SUBKEY_SIZE)
        ArxCipherCore.putLeInt(subkey, 0, x[0])
        ArxCipherCore.putLeInt(subkey, 4, x[5])
        ArxCipherCore.putLeInt(subkey, 8, x[10])
        ArxCipherCore.putLeInt(subkey, 12, x[15])
        ArxCipherCore.putLeInt(subkey, 16, x[6])
        ArxCipherCore.putLeInt(subkey, 20, x[7])
        ArxCipherCore.putLeInt(subkey, 24, x[8])
        ArxCipherCore.putLeInt(subkey, 28, x[9])
        x.fill(0)
        return subkey
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[b] = x[b] xor (x[a] + x[d]).rotateLeft(7)
        x[c] = x[c] xor (x[b] + x[a]).rotateLeft(9)
        x[d] = x[d] xor (x[c] + x[b]).rotateLeft(13)
        x[a] = x[a] xor (x[d] + x[c]).rotateLeft(18)
    }

    private fun checkKeySize(key: ByteArray) {
        require(key.size == KEY_SIZE_256) {
            "Key must be 32 bytes, was ${key.size}"
        }
    }

    private fun checkNonce(nonce: ByteArray) {
        require(nonce.size == NONCE_SIZE) {
            "Nonce must be 24 bytes, was ${nonce.size}"
        }
    }
}

