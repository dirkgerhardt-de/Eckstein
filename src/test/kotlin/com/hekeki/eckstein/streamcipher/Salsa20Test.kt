/**
 * Salsa20 - Stream cipher Salsa20
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
import org.bouncycastle.crypto.engines.Salsa20Engine
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream

class Salsa20Test {

    private val keySizes = listOf(16, 32)
    private val roundsVariants = listOf(Salsa20.ROUNDS_8, Salsa20.ROUNDS_12, Salsa20.ROUNDS_20)

    @Test
    fun `produces correct keystream for known Salsa20-20 test vector with zero key and nonce`() {
        val key = ByteArray(32)
        val nonce = ByteArray(8)
        val plain = ByteArray(64)

        assertEquals(
            "9a97f65b9b4c721b960a672145fca8d4e32e67f9111ea979ce9c4826806aeee" +
                "63de9c0da2bd7f91ebcb2639bf989c6251b29bf38d39a9bdce7c55f4b2ac12a39",
            Hex.encode(Salsa20.encrypt(key, nonce, plain))
        )
    }

    @Test
    fun `produces correct keystream for known Salsa20-20 test vector with non-zero 256-bit key`() {
        val key = ByteArray(32) { i -> (i + 1).toByte() }
        val nonce = ByteArray(8) { i -> (i + 1).toByte() }
        val plain = ByteArray(64)

        assertEquals(
            "67d3c3a70cf9352b1b35f4babe33ef661658105cad7e18a42496bc51119accd" +
                "40953038a9573de32922d9b34660c044637dfdc77037b62c8ca4576ef4c08f650",
            Hex.encode(Salsa20.encrypt(key, nonce, plain))
        )
    }

    @Test
    fun `produces correct keystream for known Salsa20-20 test vector with 128-bit key`() {
        val key = ByteArray(16) { i -> (i + 1).toByte() }
        val nonce = ByteArray(8)
        val plain = ByteArray(64)

        assertEquals(
            "8cf09a0a5fab111ee03e96a1dcb4e597c87d3c5ad3e4ce7c889f73f2300e793" +
                "9de74c260d453f9ceed6017f7eceb3cb5ac7a020832210ddc113904f8bdd571e3",
            Hex.encode(Salsa20.encrypt(key, nonce, plain))
        )
    }


    @Test
    fun `encrypt matches BouncyCastle reference for all key sizes and round variants`() {
        for (keySize in keySizes) {
            for (rounds in roundsVariants) {
                val key = Utils.randomBytes(keySize)
                val nonce = Utils.randomBytes(Salsa20.NONCE_SIZE)
                val plain = Utils.randomBytes(200) // spans multiple 64-byte blocks

                val engine = Salsa20Engine(rounds)
                engine.init(true, ParametersWithIV(KeyParameter(key), nonce))
                val expected = ByteArray(plain.size)
                engine.processBytes(plain, 0, plain.size, expected, 0)

                val actual = Salsa20.encrypt(key, nonce, plain, rounds = rounds)
                assertArrayEquals(expected, actual, "keystream mismatch for key size $keySize rounds $rounds")
            }
        }
    }

    @Test
    fun `encrypt then decrypt returns the original plaintext`() {
        for (keySize in keySizes) {
            val key = Utils.randomBytes(keySize)
            val nonce = Salsa20.nonce()
            val plain = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an.".toByteArray()

            val cipherText = Salsa20.encrypt(key, nonce, plain)
            val decrypted = Salsa20.decrypt(key, nonce, cipherText)

            assertArrayEquals(plain, decrypted, "roundtrip mismatch for key size $keySize")
        }
    }

    @Test
    fun `initial block counter offsets the keystream like seeking`() {
        val key = Utils.randomBytes(32)
        val nonce = Utils.randomBytes(Salsa20.NONCE_SIZE)
        val plain = Utils.randomBytes(Salsa20.BLOCK_SIZE * 3)

        val fromStart = Salsa20.encrypt(key, nonce, plain)
        val fromSecondBlock = Salsa20.encrypt(
            key, nonce, plain.copyOfRange(Salsa20.BLOCK_SIZE, plain.size), counter = 1L
        )

        assertArrayEquals(
            fromStart.copyOfRange(Salsa20.BLOCK_SIZE, plain.size),
            fromSecondBlock,
            "counter offset should reproduce the keystream of later blocks"
        )
    }

    @Test
    fun `is symmetric xor cipher so double encryption returns the original plaintext`() {
        val key = Utils.randomBytes(16)
        val nonce = Salsa20.nonce()
        val plain = Utils.randomBytes(37) // not block-aligned

        val once = Salsa20.encrypt(key, nonce, plain)
        val twice = Salsa20.encrypt(key, nonce, once)

        assertArrayEquals(plain, twice)
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
    fun `invalid rounds throws`() {
        val key = Utils.randomBytes(16)
        val nonce = Utils.randomBytes(Salsa20.NONCE_SIZE)
        val plain = ByteArray(16)

        assertThrows(IllegalArgumentException::class.java) { Salsa20.encrypt(key, nonce, plain, rounds = 9) }
        assertThrows(IllegalArgumentException::class.java) { Salsa20.encrypt(key, nonce, plain, rounds = 6) }
        assertThrows(IllegalArgumentException::class.java) { Salsa20.encrypt(key, nonce, plain, rounds = 22) }
    }

    @Test
    fun `nonce() returns random 8-byte values`() {
        val a = Salsa20.nonce()
        val b = Salsa20.nonce()
        assertEquals(Salsa20.NONCE_SIZE, a.size)
        assertFalse(a.contentEquals(b))
    }

    class NamedInvocation(val name: String, val action: () -> Unit) {
        override fun toString() = name
    }

    companion object {

        @JvmStatic
        fun invalidKeyCases(): Stream<NamedInvocation> {
            val nonce = ByteArray(Salsa20.NONCE_SIZE)
            val plain = ByteArray(16)

            return Stream.of(
                NamedInvocation("key size 15") { Salsa20.encrypt(ByteArray(15), nonce, plain) },
                NamedInvocation("key size 24") { Salsa20.encrypt(ByteArray(24), nonce, plain) },
                NamedInvocation("key size 33") { Salsa20.encrypt(ByteArray(33), nonce, plain) }
            )
        }

        @JvmStatic
        fun invalidNonceCases(): Stream<NamedInvocation> {
            val key = ByteArray(Salsa20.KEY_SIZE_128)
            val plain = ByteArray(16)

            return Stream.of(
                NamedInvocation("nonce size 7") { Salsa20.encrypt(key, ByteArray(7), plain) },
                NamedInvocation("nonce size 9") { Salsa20.encrypt(key, ByteArray(9), plain) }
            )
        }
    }
}

