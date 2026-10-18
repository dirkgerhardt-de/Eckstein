/**
 * AeadCore - shared building blocks for Poly1305-based AEAD constructions
 * (ChaCha20Poly1305, XChaCha20Poly1305 and XSalsaPoly1305)
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

internal object AeadCore {

    const val TAG_SIZE = 16

    /** Splits `ciphertext || tag` into its two parts. */
    class Sealed(val ciphertext: ByteArray, val tag: ByteArray)

    fun split(sealed: ByteArray): Sealed {
        require(sealed.size >= TAG_SIZE) {
            "Ciphertext too short: ${sealed.size} bytes, need at least $TAG_SIZE for the tag"
        }
        return Sealed(
            sealed.copyOfRange(0, sealed.size - TAG_SIZE),
            sealed.copyOfRange(sealed.size - TAG_SIZE, sealed.size)
        )
    }

    /** Verifies the tag (constant time) and throws [SecurityException] on mismatch. */
    fun requireValidTag(tag: ByteArray, oneTimeKey: ByteArray, macInput: ByteArray) {
        if (!Poly1305.verify(tag, oneTimeKey, macInput)) {
            throw SecurityException("Authentication failed")
        }
    }

    /**
     * MAC input of the RFC 8439 construction:
     * pad16(aad) || pad16(ciphertext) || le64(len(aad)) || le64(len(ciphertext))
     */
    fun macData(aad: ByteArray, ciphertext: ByteArray): ByteArray {
        val data = ByteArray(paddedLength(aad.size) + paddedLength(ciphertext.size) + 16)
        var offset = copyWithPadding(aad, data, 0)
        offset = copyWithPadding(ciphertext, data, offset)
        putLe64(data, offset, aad.size.toLong())
        putLe64(data, offset + 8, ciphertext.size.toLong())
        return data
    }

    private fun paddedLength(len: Int): Int = if (len % 16 == 0) len else len + (16 - len % 16)

    private fun copyWithPadding(source: ByteArray, dest: ByteArray, destOffset: Int): Int {
        System.arraycopy(source, 0, dest, destOffset, source.size)
        return destOffset + paddedLength(source.size) // remaining bytes stay zero
    }

    private fun putLe64(dest: ByteArray, offset: Int, value: Long) {
        for (i in 0 until 8) {
            dest[offset + i] = ((value ushr (8 * i)) and 0xFF).toByte()
        }
    }
}


