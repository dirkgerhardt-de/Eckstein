/**
 * Poly1305AES - Message Authentication Code (MAC) based on Poly1305 and AES
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
package com.hekeki.eckstein.mac

import com.hekeki.eckstein.blockcipher.AES

object Poly1305AES {

    private const val KEY_SIZE = 32
    private const val NONCE_SIZE = 16
    private const val TAG_SIZE = 16

    fun authenticate(message: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {

        require(key.size == KEY_SIZE) { "key must be $KEY_SIZE bytes, but was ${key.size}" }
        require(nonce.size == NONCE_SIZE) { "nonce must be $NONCE_SIZE bytes, but was ${nonce.size}" }

        val rPart = key.copyOfRange(0, 16)
        val aesKey = key.copyOfRange(16, 32)
        val s = AES.encryptECB(nonce, aesKey)

        val tag = Poly1305.authenticate(message, rPart + s)
        check(tag.size == TAG_SIZE) { "internal error: expected tag of $TAG_SIZE bytes, but was ${tag.size}" }
        return tag
    }

    fun verify(mac: ByteArray, message: ByteArray, nonce: ByteArray, key: ByteArray): Boolean {

        val expected = authenticate(message, nonce, key)
        var diff = expected.size xor mac.size
        var i = 0
        while (i < expected.size && i < mac.size) {
            diff = diff or (expected[i].toInt() xor mac[i].toInt())
            i++
        }
        return diff == 0
    }
}