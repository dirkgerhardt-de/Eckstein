/**
 * ChaCha20Poly1305 - authenticated encryption with associated data (AEAD) using ChaCha20 and Poly1305.
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
package com.hekeki.eckstein.aead

import com.hekeki.eckstein.mac.Poly1305
import com.hekeki.eckstein.streamcipher.ChaCha20

object ChaCha20Poly1305 {

    const val KEY_SIZE = 32
    const val NONCE_SIZE = 12
    const val TAG_SIZE = AeadCore.TAG_SIZE
    private const val COUNTER_START = 1L

    fun nonce(): ByteArray = ChaCha20.nonce(ietf = true)

    fun encrypt(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray = ByteArray(0)
    ): ByteArray {
        checkParameters(key, nonce)

        val oneTimeKey = deriveOneTimeKey(key, nonce)
        val ciphertext = ChaCha20.encrypt(key, nonce, plaintext, COUNTER_START)

        val tag = Poly1305.authenticate(AeadCore.macData(aad, ciphertext), oneTimeKey)

        return ciphertext + tag
    }

    fun decrypt(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray = ByteArray(0)
    ): ByteArray {
        checkParameters(key, nonce)
        val sealed = AeadCore.split(ciphertext)

        val oneTimeKey = deriveOneTimeKey(key, nonce)
        AeadCore.requireValidTag(sealed.tag, oneTimeKey, AeadCore.macData(aad, sealed.ciphertext))

        return ChaCha20.decrypt(key, nonce, sealed.ciphertext, COUNTER_START)
    }

    fun verify(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray = ByteArray(0)
    ): Boolean {
        return try {
            decrypt(key, nonce, ciphertext, aad)
            true
        } catch (e: SecurityException) {
            false
        }
    }

    private fun deriveOneTimeKey(key: ByteArray, nonce: ByteArray): ByteArray {
        val keystream = ChaCha20.encrypt(key, nonce, ByteArray(Poly1305.KEY_SIZE), 0L)
        return keystream
    }


    private fun checkParameters(key: ByteArray, nonce: ByteArray) {
        require(key.size == KEY_SIZE) { "Key must be $KEY_SIZE bytes, but was ${key.size}" }
        require(nonce.size == NONCE_SIZE) { "Nonce must be $NONCE_SIZE bytes, but was ${nonce.size}" }
    }
}