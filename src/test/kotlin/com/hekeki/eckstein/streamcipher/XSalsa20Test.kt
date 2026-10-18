/**
 * XSalsa20Test - Tests for XSalsa20
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

import org.bouncycastle.crypto.engines.XSalsa20Engine
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.util.Random

class XSalsa20Test {

    private fun bc(key: ByteArray, nonce: ByteArray, data: ByteArray): ByteArray {
        val engine = XSalsa20Engine()
        engine.init(true, ParametersWithIV(KeyParameter(key), nonce))
        val out = ByteArray(data.size)
        engine.processBytes(data, 0, data.size, out, 0)
        return out
    }

    @Test
    fun `matches BouncyCastle for various lengths`() {
        val rnd = Random(42)
        for (len in intArrayOf(0, 1, 63, 64, 65, 128, 1000, 4096)) {
            val key = ByteArray(32).also { rnd.nextBytes(it) }
            val nonce = ByteArray(24).also { rnd.nextBytes(it) }
            val data = ByteArray(len).also { rnd.nextBytes(it) }
            assertArrayEquals(bc(key, nonce, data), XSalsa20.encrypt(key, nonce, data), "len=$len")
        }
    }

    @Test
    fun `encrypt and decrypt roundtrip`() {
        val key = ByteArray(32) { it.toByte() }
        val nonce = XSalsa20.nonce()
        val data = "Hello XSalsa20".toByteArray()
        assertArrayEquals(data, XSalsa20.decrypt(key, nonce, XSalsa20.encrypt(key, nonce, data)))
    }

    @Test
    fun `rejects invalid key and nonce sizes`() {
        assertThrows(IllegalArgumentException::class.java) {
            XSalsa20.encrypt(ByteArray(16), ByteArray(24), ByteArray(1))
        }
        assertThrows(IllegalArgumentException::class.java) {
            XSalsa20.encrypt(ByteArray(32), ByteArray(8), ByteArray(1))
        }
    }
}

