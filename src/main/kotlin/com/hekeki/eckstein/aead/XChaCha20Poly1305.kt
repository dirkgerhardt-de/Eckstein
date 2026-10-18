/**
 * XChaCha20Poly1305 - authenticated encryption with associated data (AEAD) using XChaCha20 and Poly1305.
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

import com.hekeki.eckstein.streamcipher.XChaCha20

object XChaCha20Poly1305 {

    const val KEY_SIZE = 32
    const val NONCE_SIZE = XChaCha20.NONCE_SIZE
    const val TAG_SIZE = AeadCore.TAG_SIZE

    private const val HCHACHA20_NONCE_SIZE = 16

    fun nonce(): ByteArray = XChaCha20.nonce()

    fun encrypt(
        key: ByteArray,
        nonce: ByteArray,
        plaintext: ByteArray,
        aad: ByteArray = ByteArray(0)
    ): ByteArray {
        checkParameters(key, nonce)
        val subkey = deriveSubkey(key, nonce)
        try {
            return ChaCha20Poly1305.encrypt(subkey, XChaCha20.chaChaNonce(nonce), plaintext, aad)
        } finally {
            subkey.fill(0)
        }
    }

    fun decrypt(
        key: ByteArray,
        nonce: ByteArray,
        ciphertext: ByteArray,
        aad: ByteArray = ByteArray(0)
    ): ByteArray {
        checkParameters(key, nonce)
        val subkey = deriveSubkey(key, nonce)
        try {
            return ChaCha20Poly1305.decrypt(subkey, XChaCha20.chaChaNonce(nonce), ciphertext, aad)
        } finally {
            subkey.fill(0)
        }
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

    private fun deriveSubkey(key: ByteArray, nonce: ByteArray): ByteArray =
        XChaCha20.hChaCha20(key, nonce.copyOfRange(0, HCHACHA20_NONCE_SIZE))

    private fun checkParameters(key: ByteArray, nonce: ByteArray) {
        require(key.size == KEY_SIZE) { "Key must be $KEY_SIZE bytes, but was ${key.size}" }
        require(nonce.size == NONCE_SIZE) { "Nonce must be $NONCE_SIZE bytes, but was ${nonce.size}" }
    }
}

