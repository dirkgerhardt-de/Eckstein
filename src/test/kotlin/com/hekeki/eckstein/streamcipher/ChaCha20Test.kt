/**
 * ChaCha20 - Encryption and decryption with ChaCha20
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
import org.bouncycastle.crypto.engines.ChaCha7539Engine
import org.bouncycastle.crypto.engines.ChaChaEngine
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.MethodSource
import java.util.stream.Stream

class ChaCha20Test {

    private val roundsVariants = listOf(ChaCha20.ROUNDS_8, ChaCha20.ROUNDS_12, ChaCha20.ROUNDS_20)

    @Test
    fun `produces correct keystream for RFC 8439 test vector with zero key and nonce`() {
        // RFC 8439, section 2.4.2, block counter 0
        val key = ByteArray(32)
        val nonce = ByteArray(12)
        val plain = ByteArray(64)

        assertEquals(
            "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc" +
                "7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586",
            Hex.encode(ChaCha20.encrypt(key, nonce, plain))
        )
    }

    @Test
    fun `produces correct keystream for known IETF test vector with sequential key and nonce`() {
        val key = ByteArray(32) { i -> (i + 1).toByte() }
        val nonce = ByteArray(12) { i -> (i + 1).toByte() }
        val plain = ByteArray(64)

        assertEquals(
            "0209c3402579e40d6e7314689370ec705273c66cc921d285e9732e057bd2111" +
                "641dea74ce6b50345b34db673670d8b12a689f4c4e05fe3c5e79b63af01404886",
            Hex.encode(ChaCha20.encrypt(key, nonce, plain))
        )
    }

    @Test
    fun `produces correct keystream for known original DJB variant test vector with 128-bit key`() {
        val key = ByteArray(16) { i -> (i + 1).toByte() }
        val nonce = ByteArray(8)
        val plain = ByteArray(64)

        assertEquals(
            "ef9a4f2946694bf1c56f4b801a97fc213fb8844e9adc8ec22777d7c7be16590" +
                "31c7ab577c209fb1199b5f2ed72210a46e1504bf9dec3ffbae84a8215df578b40",
            Hex.encode(ChaCha20.encrypt(key, nonce, plain))
        )
    }

    @Test
    fun `IETF variant matches BouncyCastle ChaCha7539 reference for arbitrary lengths`() {
        for (len in listOf(1, 15, 16, 17, 63, 64, 65, 200)) {
            val key = Utils.randomBytes(ChaCha20.KEY_SIZE_256)
            val nonce = Utils.randomBytes(ChaCha20.NONCE_SIZE_IETF)
            val plain = Utils.randomBytes(len)

            val engine = ChaCha7539Engine()
            engine.init(true, ParametersWithIV(KeyParameter(key), nonce))
            val expected = ByteArray(len)
            engine.processBytes(plain, 0, len, expected, 0)

            val actual = ChaCha20.encrypt(key, nonce, plain)
            assertArrayEquals(expected, actual, "IETF keystream mismatch for len $len")
        }
    }

    @Test
    fun `original DJB variant matches BouncyCastle ChaChaEngine reference for all key sizes and round variants`() {
        for (keySize in listOf(ChaCha20.KEY_SIZE_128, ChaCha20.KEY_SIZE_256)) {
            for (rounds in roundsVariants) {
                val key = Utils.randomBytes(keySize)
                val nonce = Utils.randomBytes(ChaCha20.NONCE_SIZE_ORIGINAL)
                val plain = Utils.randomBytes(200)

                val engine = ChaChaEngine(rounds)
                engine.init(true, ParametersWithIV(KeyParameter(key), nonce))
                val expected = ByteArray(plain.size)
                engine.processBytes(plain, 0, plain.size, expected, 0)

                val actual = ChaCha20.encrypt(key, nonce, plain, rounds = rounds)
                assertArrayEquals(expected, actual, "keystream mismatch for key size $keySize rounds $rounds")
            }
        }
    }

    @Test
    fun `encrypt then decrypt returns the original plaintext for both nonce variants`() {
        val plain = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an.".toByteArray()

        for (keySize in listOf(ChaCha20.KEY_SIZE_128, ChaCha20.KEY_SIZE_256)) {
            val key = Utils.randomBytes(keySize)

            val ietfNonce = ChaCha20.nonce(ietf = true)
            val ietfCipher = ChaCha20.encrypt(key, ietfNonce, plain)
            assertArrayEquals(plain, ChaCha20.decrypt(key, ietfNonce, ietfCipher), "IETF roundtrip mismatch for key size $keySize")

            val origNonce = ChaCha20.nonce(ietf = false)
            val origCipher = ChaCha20.encrypt(key, origNonce, plain)
            assertArrayEquals(plain, ChaCha20.decrypt(key, origNonce, origCipher), "original roundtrip mismatch for key size $keySize")
        }
    }

    @Test
    fun `initial block counter offsets the keystream like seeking for both nonce variants`() {
        val key = Utils.randomBytes(ChaCha20.KEY_SIZE_256)

        for (nonce in listOf(ChaCha20.nonce(ietf = true), ChaCha20.nonce(ietf = false))) {
            val plain = Utils.randomBytes(ChaCha20.BLOCK_SIZE * 3)

            val fromStart = ChaCha20.encrypt(key, nonce, plain)
            val fromSecondBlock = ChaCha20.encrypt(
                key, nonce, plain.copyOfRange(ChaCha20.BLOCK_SIZE, plain.size), counter = 1L
            )

            assertArrayEquals(
                fromStart.copyOfRange(ChaCha20.BLOCK_SIZE, plain.size),
                fromSecondBlock,
                "counter offset should reproduce the keystream of later blocks (nonce size ${nonce.size})"
            )
        }
    }

    @Test
    fun `is symmetric xor cipher so double encryption returns the original plaintext`() {
        val key = Utils.randomBytes(ChaCha20.KEY_SIZE_128)
        val nonce = ChaCha20.nonce()
        val plain = Utils.randomBytes(37) // not block-aligned

        val once = ChaCha20.encrypt(key, nonce, plain)
        val twice = ChaCha20.encrypt(key, nonce, once)

        assertArrayEquals(plain, twice)
    }

    @Test
    fun `counter exceeding 32 bits throws for IETF nonce but is allowed for original nonce`() {
        val key = Utils.randomBytes(ChaCha20.KEY_SIZE_256)
        val plain = ByteArray(16)

        val ietfNonce = Utils.randomBytes(ChaCha20.NONCE_SIZE_IETF)
        assertThrows(IllegalArgumentException::class.java) {
            ChaCha20.encrypt(key, ietfNonce, plain, counter = 1L shl 32)
        }

        val origNonce = Utils.randomBytes(ChaCha20.NONCE_SIZE_ORIGINAL)
        assertDoesNotThrow {
            ChaCha20.encrypt(key, origNonce, plain, counter = 1L shl 32)
        }
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
        val key = Utils.randomBytes(ChaCha20.KEY_SIZE_128)
        val nonce = Utils.randomBytes(ChaCha20.NONCE_SIZE_IETF)
        val plain = ByteArray(16)

        assertThrows(IllegalArgumentException::class.java) { ChaCha20.encrypt(key, nonce, plain, rounds = 9) }
        assertThrows(IllegalArgumentException::class.java) { ChaCha20.encrypt(key, nonce, plain, rounds = 6) }
        assertThrows(IllegalArgumentException::class.java) { ChaCha20.encrypt(key, nonce, plain, rounds = 22) }
    }

    @Test
    fun `nonce() returns random values with the requested size`() {
        val ietf = ChaCha20.nonce(ietf = true)
        val original = ChaCha20.nonce(ietf = false)
        assertEquals(ChaCha20.NONCE_SIZE_IETF, ietf.size)
        assertEquals(ChaCha20.NONCE_SIZE_ORIGINAL, original.size)
        assertFalse(ietf.contentEquals(ChaCha20.nonce(ietf = true)))
    }

    class NamedInvocation(val name: String, val action: () -> Unit) {
        override fun toString() = name
    }

    companion object {

        @JvmStatic
        fun invalidKeyCases(): Stream<NamedInvocation> {
            val nonce = ByteArray(ChaCha20.NONCE_SIZE_IETF)
            val plain = ByteArray(16)

            return Stream.of(
                NamedInvocation("key size 15") { ChaCha20.encrypt(ByteArray(15), nonce, plain) },
                NamedInvocation("key size 24") { ChaCha20.encrypt(ByteArray(24), nonce, plain) },
                NamedInvocation("key size 33") { ChaCha20.encrypt(ByteArray(33), nonce, plain) }
            )
        }

        @JvmStatic
        fun invalidNonceCases(): Stream<NamedInvocation> {
            val key = ByteArray(ChaCha20.KEY_SIZE_128)
            val plain = ByteArray(16)

            return Stream.of(
                NamedInvocation("nonce size 7") { ChaCha20.encrypt(key, ByteArray(7), plain) },
                NamedInvocation("nonce size 9") { ChaCha20.encrypt(key, ByteArray(9), plain) },
                NamedInvocation("nonce size 11") { ChaCha20.encrypt(key, ByteArray(11), plain) },
                NamedInvocation("nonce size 13") { ChaCha20.encrypt(key, ByteArray(13), plain) }
            )
        }
    }
}

