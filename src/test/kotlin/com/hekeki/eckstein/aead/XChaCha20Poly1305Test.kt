/**
 * XChaCha20Poly1305Test - Tests for XChaCha20Poly1305
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

import com.hekeki.eckstein.utils.Utils
import org.bouncycastle.crypto.modes.ChaCha20Poly1305 as BcChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class XChaCha20Poly1305Test {

    @Test
    fun `roundtrip with and without AAD`() {
        val key = Utils.randomBytes(XChaCha20Poly1305.KEY_SIZE)
        val nonce = XChaCha20Poly1305.nonce()
        val plain = "XChaCha20-Poly1305 roundtrip".toByteArray()
        val aad = "header".toByteArray()

        assertArrayEquals(plain, XChaCha20Poly1305.decrypt(key, nonce, XChaCha20Poly1305.encrypt(key, nonce, plain)))
        assertArrayEquals(
            plain,
            XChaCha20Poly1305.decrypt(key, nonce, XChaCha20Poly1305.encrypt(key, nonce, plain, aad), aad)
        )
    }

    @Test
    fun `equals ChaCha20Poly1305 with HChaCha20 subkey (BouncyCastle reference)`() {
        for (len in listOf(0, 1, 16, 63, 64, 65, 200)) {
            val key = Utils.randomBytes(32)
            val nonce = Utils.randomBytes(24)
            val plain = if (len == 0) ByteArray(0) else Utils.randomBytes(len)
            val aad = Utils.randomBytes(13)

            val subkey = com.hekeki.eckstein.streamcipher.XChaCha20.hChaCha20(key, nonce.copyOfRange(0, 16))
            val ietfNonce = ByteArray(12)
            System.arraycopy(nonce, 16, ietfNonce, 4, 8)

            val bc = BcChaCha20Poly1305()
            bc.init(true, AEADParameters(KeyParameter(subkey), 128, ietfNonce, aad))
            val expected = ByteArray(bc.getOutputSize(plain.size))
            val n = bc.processBytes(plain, 0, plain.size, expected, 0)
            bc.doFinal(expected, n)

            assertArrayEquals(expected, XChaCha20Poly1305.encrypt(key, nonce, plain, aad), "len=$len")
        }
    }

    @Test
    fun `tampering is detected`() {
        val key = Utils.randomBytes(32)
        val nonce = XChaCha20Poly1305.nonce()
        val sealed = XChaCha20Poly1305.encrypt(key, nonce, "secret".toByteArray())

        sealed[0] = (sealed[0].toInt() xor 1).toByte()
        assertThrows(SecurityException::class.java) { XChaCha20Poly1305.decrypt(key, nonce, sealed) }
        assertFalse(XChaCha20Poly1305.verify(key, nonce, sealed))
    }

    @Test
    fun `rejects invalid sizes`() {
        assertThrows(IllegalArgumentException::class.java) {
            XChaCha20Poly1305.encrypt(ByteArray(16), ByteArray(24), ByteArray(1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            XChaCha20Poly1305.encrypt(ByteArray(32), ByteArray(12), ByteArray(1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            XChaCha20Poly1305.decrypt(ByteArray(32), ByteArray(24), ByteArray(5))
        }
    }
}

