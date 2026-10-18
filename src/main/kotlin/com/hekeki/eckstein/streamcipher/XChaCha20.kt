/**
 * XChaCha20 - Extended-nonce variant of ChaCha20 (192-bit / 24-byte nonce)
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

object XChaCha20 {

    const val ROUNDS_20 = ArxCipherCore.ROUNDS_20
    const val ROUNDS_12 = ArxCipherCore.ROUNDS_12
    const val ROUNDS_8 = ArxCipherCore.ROUNDS_8
    const val KEY_SIZE_256 = ArxCipherCore.KEY_SIZE_256
    const val NONCE_SIZE = 24 // 192-bit nonce (16 bytes for HChaCha20 + 8 bytes for ChaCha20)
    const val SUBKEY_SIZE = 32 // 256-bit subkey

    private const val HCHACHA20_NONCE_SIZE = 16 // 128-bit nonce consumed by HChaCha20
    private const val STATE_WORDS = ArxCipherCore.STATE_WORDS

    fun nonce(): ByteArray = ArxCipherCore.randomBytes(NONCE_SIZE)

    fun encrypt(
        key: ByteArray, nonce: ByteArray, plaintext: ByteArray,
        counter: Long = 0L, rounds: Int = ROUNDS_20
    ): ByteArray {
        checkKeySize(key)
        checkNonce(nonce)

        val subkey = hChaCha20(key, nonce.copyOfRange(0, HCHACHA20_NONCE_SIZE), rounds)
        return ChaCha20.encrypt(subkey, chaChaNonce(nonce), plaintext, counter, rounds)
    }

    fun decrypt(
        key: ByteArray, nonce: ByteArray, ciphertext: ByteArray,
        counter: Long = 0L, rounds: Int = ROUNDS_20
    ): ByteArray {
        checkKeySize(key)
        checkNonce(nonce)

        val subkey = hChaCha20(key, nonce.copyOfRange(0, HCHACHA20_NONCE_SIZE), rounds)
        return ChaCha20.decrypt(subkey, chaChaNonce(nonce), ciphertext, counter, rounds)
    }

    internal fun chaChaNonce(nonce: ByteArray): ByteArray {
        val chachaNonce = ByteArray(ChaCha20.NONCE_SIZE_IETF)
        System.arraycopy(nonce, HCHACHA20_NONCE_SIZE, chachaNonce, 4, NONCE_SIZE - HCHACHA20_NONCE_SIZE)
        return chachaNonce
    }

    /**
     * HChaCha20 - Subkey derivation for XChaCha20.
     */
    fun hChaCha20(key: ByteArray, nonce: ByteArray, rounds: Int = ROUNDS_20): ByteArray {
        require(key.size == KEY_SIZE_256) {
            "HChaCha20 requires 256-bit key, was ${key.size} bytes"
        }
        require(nonce.size == HCHACHA20_NONCE_SIZE) {
            "HChaCha20 requires 128-bit nonce, was ${nonce.size} bytes"
        }
        require(rounds in listOf(ROUNDS_8, ROUNDS_12, ROUNDS_20)) {
            "Rounds must be 8, 12, or 20, was $rounds"
        }

        val k = ArxCipherCore.expandKeyWords(key)

        // State layout (RFC 8439 Section 2.8 / draft-irtf-cfrg-xchacha):
        //   σ₀ σ₁ σ₂ σ₃     ← constants
        //   k₀ k₁ k₂ k₃     ← key words 0-3
        //   k₄ k₅ k₆ k₇     ← key words 4-7
        //   n₀ n₁ n₂ n₃     ← nonce words 0-3 (full 128-bit nonce)
        val state = IntArray(STATE_WORDS)
        state[0] = ArxCipherCore.SIGMA[0]
        state[1] = ArxCipherCore.SIGMA[1]
        state[2] = ArxCipherCore.SIGMA[2]
        state[3] = ArxCipherCore.SIGMA[3]
        for (i in 0 until ArxCipherCore.KEY_WORDS) state[4 + i] = k[i]
        state[12] = ArxCipherCore.leInt(nonce, 0)
        state[13] = ArxCipherCore.leInt(nonce, 4)
        state[14] = ArxCipherCore.leInt(nonce, 8)
        state[15] = ArxCipherCore.leInt(nonce, 12)

        val work = state.copyOf()
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

        // Extract subkey from words 0-3 and 12-15 (256 bits = 8 x 32-bit words), no feed-forward
        val subkey = ByteArray(SUBKEY_SIZE)
        ArxCipherCore.putLeInt(subkey, 0, work[0])
        ArxCipherCore.putLeInt(subkey, 4, work[1])
        ArxCipherCore.putLeInt(subkey, 8, work[2])
        ArxCipherCore.putLeInt(subkey, 12, work[3])
        ArxCipherCore.putLeInt(subkey, 16, work[12])
        ArxCipherCore.putLeInt(subkey, 20, work[13])
        ArxCipherCore.putLeInt(subkey, 24, work[14])
        ArxCipherCore.putLeInt(subkey, 28, work[15])

        return subkey
    }

    private fun quarterRound(x: IntArray, a: Int, b: Int, c: Int, d: Int) {
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(16)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(12)
        x[a] += x[b]; x[d] = (x[d] xor x[a]).rotateLeft(8)
        x[c] += x[d]; x[b] = (x[b] xor x[c]).rotateLeft(7)
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

