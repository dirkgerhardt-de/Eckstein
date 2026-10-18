/**
 * XSalsaPoly1305Test - Tests for XSalsaPoly1305 (NaCl secretbox)
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
import org.bouncycastle.crypto.engines.XSalsa20Engine
import org.bouncycastle.crypto.macs.Poly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class XSalsaPoly1305Test {

    /** Reference secretbox built from BouncyCastle primitives. */
    private fun reference(key: ByteArray, nonce: ByteArray, plain: ByteArray): ByteArray {
        val engine = XSalsa20Engine()
        engine.init(true, ParametersWithIV(KeyParameter(key), nonce))
        val input = ByteArray(32) + plain
        val stream = ByteArray(input.size)
        engine.processBytes(input, 0, input.size, stream, 0)

        val ct = stream.copyOfRange(32, stream.size)
        val mac = Poly1305()
        mac.init(KeyParameter(stream.copyOfRange(0, 32)))
        mac.update(ct, 0, ct.size)
        val tag = ByteArray(16)
        mac.doFinal(tag, 0)
        return tag + ct
    }

    @Test
    fun `matches reference built from BouncyCastle primitives`() {
        for (len in listOf(0, 1, 31, 32, 33, 63, 64, 65, 200, 1000)) {
            val key = Utils.randomBytes(32)
            val nonce = Utils.randomBytes(24)
            val plain = if (len == 0) ByteArray(0) else Utils.randomBytes(len)
            assertArrayEquals(reference(key, nonce, plain), XSalsaPoly1305.encrypt(key, nonce, plain), "len=$len")
        }
    }

    @Test
    fun `roundtrip`() {
        val key = Utils.randomBytes(32)
        val nonce = XSalsaPoly1305.nonce()
        val plain = "NaCl secretbox".toByteArray()
        assertArrayEquals(plain, XSalsaPoly1305.decrypt(key, nonce, XSalsaPoly1305.encrypt(key, nonce, plain)))
    }

    @Test
    fun `tampering is detected`() {
        val key = Utils.randomBytes(32)
        val nonce = XSalsaPoly1305.nonce()
        val sealed = XSalsaPoly1305.encrypt(key, nonce, "secret".toByteArray())

        for (idx in listOf(0, sealed.size - 1)) {
            val bad = sealed.copyOf()
            bad[idx] = (bad[idx].toInt() xor 1).toByte()
            assertThrows(SecurityException::class.java) { XSalsaPoly1305.decrypt(key, nonce, bad) }
            assertFalse(XSalsaPoly1305.verify(key, nonce, bad))
        }
    }

    @Test
    fun `rejects invalid sizes`() {
        assertThrows(IllegalArgumentException::class.java) {
            XSalsaPoly1305.encrypt(ByteArray(16), ByteArray(24), ByteArray(1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            XSalsaPoly1305.encrypt(ByteArray(32), ByteArray(8), ByteArray(1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            XSalsaPoly1305.decrypt(ByteArray(32), ByteArray(24), ByteArray(5))
        }
    }
}

