/**
 * XSalsaPoly1305 - authenticated encryption with associated data (AEAD) using XSalsa20 and Poly1305.
 *
 * NaCl `crypto_secretbox_xsalsa20poly1305` construction
 * Wire format is NaCl/libsodium compatible: `tag (16 bytes) || ciphertext`.
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
import com.hekeki.eckstein.streamcipher.XSalsa20

object XSalsaPoly1305 {

    const val KEY_SIZE = XSalsa20.KEY_SIZE_256
    const val NONCE_SIZE = XSalsa20.NONCE_SIZE
    const val TAG_SIZE = AeadCore.TAG_SIZE

    fun nonce(): ByteArray = XSalsa20.nonce()

    /** Returns `tag || ciphertext`. */
    fun encrypt(key: ByteArray, nonce: ByteArray, plaintext: ByteArray): ByteArray {
        checkParameters(key, nonce)

        val stream = XSalsa20.encrypt(key, nonce, ByteArray(Poly1305.KEY_SIZE) + plaintext)
        val oneTimeKey = stream.copyOfRange(0, Poly1305.KEY_SIZE)
        val ciphertext = stream.copyOfRange(Poly1305.KEY_SIZE, stream.size)
        try {
            val tag = Poly1305.authenticate(ciphertext, oneTimeKey)
            return tag + ciphertext
        } finally {
            oneTimeKey.fill(0)
            stream.fill(0)
        }
    }

    /** Expects `tag || ciphertext`; throws [SecurityException] if authentication fails. */
    fun decrypt(key: ByteArray, nonce: ByteArray, sealed: ByteArray): ByteArray {
        checkParameters(key, nonce)
        require(sealed.size >= TAG_SIZE) {
            "Ciphertext too short: ${sealed.size} bytes, need at least $TAG_SIZE for the tag"
        }

        val tag = sealed.copyOfRange(0, TAG_SIZE)
        val ciphertext = sealed.copyOfRange(TAG_SIZE, sealed.size)

        val stream = XSalsa20.decrypt(key, nonce, ByteArray(Poly1305.KEY_SIZE) + ciphertext)
        val oneTimeKey = stream.copyOfRange(0, Poly1305.KEY_SIZE)
        try {
            AeadCore.requireValidTag(tag, oneTimeKey, ciphertext)
            // stream = keystream[0..32] || plaintext
            return stream.copyOfRange(Poly1305.KEY_SIZE, stream.size)
        } finally {
            oneTimeKey.fill(0)
            stream.fill(0)
        }
    }

    fun verify(key: ByteArray, nonce: ByteArray, sealed: ByteArray): Boolean {
        return try {
            decrypt(key, nonce, sealed)
            true
        } catch (e: SecurityException) {
            false
        }
    }

    private fun checkParameters(key: ByteArray, nonce: ByteArray) {
        require(key.size == KEY_SIZE) { "Key must be $KEY_SIZE bytes, but was ${key.size}" }
        require(nonce.size == NONCE_SIZE) { "Nonce must be $NONCE_SIZE bytes, but was ${nonce.size}" }
    }
}

