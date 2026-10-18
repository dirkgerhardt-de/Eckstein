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

import com.hekeki.eckstein.encoding.Hex
import com.hekeki.eckstein.utils.Utils
import org.bouncycastle.crypto.engines.XChaCha20Engine
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream

class XChaCha20Test {

    @Test
    fun `produces correct keystream for zero key and nonce`() {
        val key = ByteArray(32)
        val nonce = ByteArray(24)
        val plain = ByteArray(64)

        assertEquals(
            "bcd02a18bf3f01d19292de30a7a8fdaca4b65e50a6002cc72cd6d2f7c91ac3d" +
                "5728f83e0aad2bfcf9abd2d2db58faedd65015dd83fc09b131e271043019e8e0f",
            Hex.encode(XChaCha20.encrypt(key, nonce, plain))
        )
    }

    @Test
    fun `produces correct keystream for sequential key and nonce`() {
        val key = ByteArray(32) { i -> (i + 1).toByte() }
        val nonce = ByteArray(24) { i -> (i + 1).toByte() }
        val plain = ByteArray(64)

        assertEquals(
            "5bdd2fce7a411ad2f60fb12c99bdf837b3ef02a0cf894a7041840f91c017fd0" +
                "983d602d045dc7dbd8ed060364c56e04bb6d38e6a82263bd50b4123bf3e2ef9ec",
            Hex.encode(XChaCha20.encrypt(key, nonce, plain))
        )
    }

    @Test
    fun `matches BouncyCastle XChaCha20Engine reference for arbitrary lengths`() {
        for (len in listOf(1, 15, 16, 17, 63, 64, 65, 200)) {
            val key = Utils.randomBytes(XChaCha20.KEY_SIZE_256)
            val nonce = Utils.randomBytes(XChaCha20.NONCE_SIZE)
            val plain = Utils.randomBytes(len)

            val engine = XChaCha20Engine()
            engine.init(true, ParametersWithIV(KeyParameter(key), nonce))
            val expected = ByteArray(len)
            engine.processBytes(plain, 0, len, expected, 0)

            val actual = XChaCha20.encrypt(key, nonce, plain)
            assertArrayEquals(expected, actual, "XChaCha20 keystream mismatch for len $len")
        }
    }

    @Test
    fun `encrypt then decrypt returns the original plaintext`() {
        val key = Utils.randomBytes(XChaCha20.KEY_SIZE_256)
        val nonce = XChaCha20.nonce()
        val plain = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an.".toByteArray()

        val cipherText = XChaCha20.encrypt(key, nonce, plain)
        val decrypted = XChaCha20.decrypt(key, nonce, cipherText)

        assertArrayEquals(plain, decrypted)
    }

    @Test
    fun `initial block counter offsets the keystream like seeking`() {
        val key = Utils.randomBytes(XChaCha20.KEY_SIZE_256)
        val nonce = XChaCha20.nonce()
        val plain = Utils.randomBytes(64 * 3)

        val fromStart = XChaCha20.encrypt(key, nonce, plain)
        val fromSecondBlock = XChaCha20.encrypt(key, nonce, plain.copyOfRange(64, plain.size), counter = 1L)

        assertArrayEquals(fromStart.copyOfRange(64, plain.size), fromSecondBlock)
    }

    @Test
    fun `is symmetric xor cipher so double encryption returns the original plaintext`() {
        val key = Utils.randomBytes(XChaCha20.KEY_SIZE_256)
        val nonce = XChaCha20.nonce()
        val plain = Utils.randomBytes(37) // not block-aligned

        val once = XChaCha20.encrypt(key, nonce, plain)
        val twice = XChaCha20.encrypt(key, nonce, once)

        assertArrayEquals(plain, twice)
    }

    @Test
    fun `nonce() returns random 24-byte values`() {
        val a = XChaCha20.nonce()
        val b = XChaCha20.nonce()
        assertEquals(XChaCha20.NONCE_SIZE, a.size)
        assertFalse(a.contentEquals(b))
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("invalidKeyCases")
    fun `invalid key size throws`(case: NamedInvocation) {
        assertThrows(IllegalArgumentException::class.java, case.action)
    }

    @ParameterizedTest(name = "[{index}] {0}")
    @MethodSource("invalidNonceCases")
    fun `invalid nonce size throws`(case: NamedInvocation) {
        assertThrows(IllegalArgumentException::class.java, case.action)
    }

    @Test
    fun `hChaCha20 requires a 256-bit key and 128-bit nonce`() {
        assertThrows(IllegalArgumentException::class.java) {
            XChaCha20.hChaCha20(ByteArray(16), ByteArray(16))
        }
        assertThrows(IllegalArgumentException::class.java) {
            XChaCha20.hChaCha20(ByteArray(32), ByteArray(24))
        }
    }

    class NamedInvocation(val name: String, val action: () -> Unit) {
        override fun toString() = name
    }

    companion object {

        @JvmStatic
        fun invalidKeyCases(): Stream<NamedInvocation> {
            val nonce = ByteArray(XChaCha20.NONCE_SIZE)
            val plain = ByteArray(16)

            return Stream.of(
                NamedInvocation("key size 16") { XChaCha20.encrypt(ByteArray(16), nonce, plain) },
                NamedInvocation("key size 24") { XChaCha20.encrypt(ByteArray(24), nonce, plain) },
                NamedInvocation("key size 33") { XChaCha20.encrypt(ByteArray(33), nonce, plain) }
            )
        }

        @JvmStatic
        fun invalidNonceCases(): Stream<NamedInvocation> {
            val key = ByteArray(XChaCha20.KEY_SIZE_256)
            val plain = ByteArray(16)

            return Stream.of(
                NamedInvocation("nonce size 16") { XChaCha20.encrypt(key, ByteArray(16), plain) },
                NamedInvocation("nonce size 12") { XChaCha20.encrypt(key, ByteArray(12), plain) },
                NamedInvocation("nonce size 23") { XChaCha20.encrypt(key, ByteArray(23), plain) },
                NamedInvocation("nonce size 25") { XChaCha20.encrypt(key, ByteArray(25), plain) }
            )
        }
    }
}

