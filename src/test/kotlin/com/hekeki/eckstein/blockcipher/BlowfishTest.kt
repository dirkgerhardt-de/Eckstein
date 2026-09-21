/**
 * BlowfishTest - Class to test encryption and decryption with Blowfish
 *
 * Copyright (c) 2018 - 2026 Dirk Gerhardt
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
package com.hekeki.eckstein.blockcipher

import com.hekeki.eckstein.encoding.Hex
import com.hekeki.eckstein.utils.Utils
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class BlowfishTest {

    companion object {
        private const val TEST_PLAINTEXT_DE = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
        private const val TEST_PLAINTEXT_EN = "Not block aligned!"
        private const val TEST_PLAINTEXT_CBC = "CBC test data, not block aligned"
        private const val TEST_PLAINTEXT_UTF8 = "Hällo Wörld! üöä ß 12345 - this needs padding."

        private val VALID_KEY_SIZES = listOf(4, 8, 16, 32, 56)
        private val INVALID_KEY_SIZES = listOf(3, 5, 57) // Invalid: too small, not multiple of 4, too large

        private fun createKey(size: Int): ByteArray = ByteArray(size) { i -> (i + 1).toByte() }
        private fun createIv(): ByteArray = ByteArray(8) { i -> (i + 1).toByte() }
    }

    @Test
    fun `encrypt and decrypt roundtrip with ECB mode`() {
        val plain = TEST_PLAINTEXT_DE.toByteArray()

        VALID_KEY_SIZES.forEach { size ->
            val key = createKey(size)
            val encrypted = Blowfish.encryptECB(plain, key, Padding.SCHEME.PKCS5)
            val decrypted = Blowfish.decryptECB(encrypted, key, Padding.SCHEME.PKCS5)

            assertArrayEquals(plain, decrypted, "ECB roundtrip failed for key size ${size * 8} bits")
        }
    }

    @Test
    fun `encrypt and decrypt roundtrip with CBC mode`() {
        val plain = TEST_PLAINTEXT_DE.toByteArray()
        val iv = createIv()

        VALID_KEY_SIZES.forEach { size ->
            val key = createKey(size)
            val encrypted = Blowfish.encryptCBC(plain, key, iv, Padding.SCHEME.PKCS5)
            val decrypted = Blowfish.decryptCBC(encrypted, key, iv, Padding.SCHEME.PKCS5)

            assertArrayEquals(plain, decrypted, "CBC roundtrip failed for key size ${size * 8} bits")
        }
    }

    @Test
    fun `deterministic ECB encryption with known vectors`() {
        val plain = TEST_PLAINTEXT_DE.toByteArray()

        assertEquals("ca5d938bba4e8e1b6157508bc7ad4c5abf13113ce7ef7edaed24444cc73578f2c6f8fcfda72d0b1781844776ae9497c22ad4581b074bbddb9b66bf0e3d5a4bfb6ad60ba8bc056385",
            Hex.encode(Blowfish.encryptECB(plain, createKey(16), Padding.SCHEME.PKCS5)))

        assertEquals("b9e7f10eb35b90cec9ed85d89511e26011bf1ef42b5e09edf87cb5bad7894589b7e109070366e51a931627fd320f2cc324f8558b198db6f22fde97bf9fa86faca7ed75cb4da7348d",
            Hex.encode(Blowfish.encryptECB(plain, createKey(32), Padding.SCHEME.PKCS5)))

        assertEquals("5b40583865d085f0c9dcb97f4e6ebd30610905f40cae7547201350bb6e28e8d9f3fe6cd338bb0f61b9dbec5159d1a5b32bb4b2cb8b58384b6dbc0a4ed4dea13939f9e715642222cd",
            Hex.encode(Blowfish.encryptECB(plain, createKey(56), Padding.SCHEME.PKCS5)))
    }

    @Test
    fun `deterministic CBC encryption with known vectors`() {
        val plain = TEST_PLAINTEXT_DE.toByteArray()
        val iv = createIv()

        assertEquals("ed02815de3b8269653650aeb1321daa40aa053ecb4255c3d3c130995d0a06d58c763b331ae91a2d63fbe9725ef8e4d0b1630ee4cf7f173918a42b7f3e0f12ca72fcac23068f730ad",
            Hex.encode(Blowfish.encryptCBC(plain, createKey(16), iv, Padding.SCHEME.PKCS5)))

        assertEquals("0b4e6cf4c48e0107b1741bd25f2d0d69e03cd46913d539ba6078789dd71c21e6bb18680e442d69b42dc3615f799056d9c3e208474c96ecf8aa6376587987075e207a1c1274ce41e8",
            Hex.encode(Blowfish.encryptCBC(plain, createKey(32), iv, Padding.SCHEME.PKCS5)))

        assertEquals("1d7774606210939f9616dde23eb7da294a890a8da7c0d742610dbeadb46ee619a70db0d25183a04be764cc3528f71d1ae35be1151b6043a334d28acf4b3713e4d97bfd579e176362",
            Hex.encode(Blowfish.encryptCBC(plain, createKey(56), iv, Padding.SCHEME.PKCS5)))
    }

    @Test
    fun `standard test vectors - ECB`() {
        // Test vector 1
        assertEquals("6b5c5a9c5d9e0a5a",
            Hex.encode(Blowfish.encryptECB(Hex.toByteArray("ffffffffffffffff"), Hex.toByteArray("fedcba9876543210"))))

        assertEquals("ffffffffffffffff",
            Hex.encode(Blowfish.decryptECB(Hex.toByteArray("6b5c5a9c5d9e0a5a"), Hex.toByteArray("fedcba9876543210"))))

        // Test vector 2
        assertEquals("a25e7856cf2651eb",
            Hex.encode(Blowfish.encryptECB(Hex.toByteArray("51454b582ddf440a"), Hex.toByteArray("3849674c2602319e"))))

        assertEquals("51454b582ddf440a",
            Hex.encode(Blowfish.decryptECB(Hex.toByteArray("a25e7856cf2651eb"), Hex.toByteArray("3849674c2602319e"))))
    }

    @Test
    fun `standard test vectors - CBC`() {
        // Test vector 1
        assertEquals("7d9d0f14f0177e6235e32f0c97b37a5f",
            Hex.encode(Blowfish.encryptCBC(
                Hex.toByteArray("452031C1E4FADA8E0FDDDE1A8A5B83F0"),
                Hex.toByteArray("584023641ABA6176"),
                Hex.toByteArray("004BD6EF09176062"))))

        // Test vector 2
        assertEquals("73e184b02df518aad1df9a37054586ad",
            Hex.encode(Blowfish.encryptCBC(
                Hex.toByteArray("7555AE39F59B87BDFEBD1D7E17CBCA41"),
                Hex.toByteArray("025816164629B007"),
                Hex.toByteArray("480D39006EE762F2"))))
    }

    @Test
    fun `ECB matches javax crypto reference for all valid key sizes`() {
        VALID_KEY_SIZES.forEach { keySize ->
            val key = Utils.randomBytes(keySize)
            val plain = Utils.randomBytes(32) // 4 blocks of 8 bytes

            val cipher = Cipher.getInstance("Blowfish/ECB/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "Blowfish"))
            val expected = cipher.doFinal(plain)

            val actual = Blowfish.encryptECB(plain, key)
            assertArrayEquals(expected, actual, "ECB encrypt mismatch for key size ${keySize * 8} bits")

            val actualPlain = Blowfish.decryptECB(actual, key)
            assertArrayEquals(plain, actualPlain, "ECB decrypt mismatch for key size ${keySize * 8} bits")
        }
    }

    @Test
    fun `ECB with PKCS5 padding matches javax crypto`() {
        val key = Utils.randomBytes(16)
        val plain = TEST_PLAINTEXT_EN.toByteArray()

        val cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "Blowfish"))
        val expected = cipher.doFinal(plain)

        val actual = Blowfish.encryptECB(plain, key, Padding.SCHEME.PKCS5)
        assertArrayEquals(expected, actual, "ECB+PKCS5 encrypt mismatch")

        val actualPlain = Blowfish.decryptECB(actual, key, Padding.SCHEME.PKCS5)
        assertArrayEquals(plain, actualPlain, "ECB+PKCS5 decrypt mismatch")
    }

    @Test
    fun `CBC matches javax crypto reference for all valid key sizes`() {
        VALID_KEY_SIZES.forEach { keySize ->
            val key = Utils.randomBytes(keySize)
            val iv = Utils.randomBytes(8)
            val plain = Utils.randomBytes(40) // 5 blocks

            val cipher = Cipher.getInstance("Blowfish/CBC/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "Blowfish"), IvParameterSpec(iv))
            val expected = cipher.doFinal(plain)

            val actual = Blowfish.encryptCBC(plain, key, iv)
            assertArrayEquals(expected, actual, "CBC encrypt mismatch for key size ${keySize * 8} bits")

            val actualPlain = Blowfish.decryptCBC(actual, key, iv)
            assertArrayEquals(plain, actualPlain, "CBC decrypt mismatch for key size ${keySize * 8} bits")
        }
    }

    @Test
    fun `CBC with PKCS5 padding matches javax crypto`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(8)
        val plain = TEST_PLAINTEXT_CBC.toByteArray()

        val cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "Blowfish"), IvParameterSpec(iv))
        val expected = cipher.doFinal(plain)

        val actual = Blowfish.encryptCBC(plain, key, iv, Padding.SCHEME.PKCS5)
        assertArrayEquals(expected, actual, "CBC+PKCS5 encrypt mismatch")

        val actualPlain = Blowfish.decryptCBC(actual, key, iv, Padding.SCHEME.PKCS5)
        assertArrayEquals(plain, actualPlain, "CBC+PKCS5 decrypt mismatch")
    }

    @Test
    fun `UTF-8 roundtrip with special characters`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(8)
        val text = TEST_PLAINTEXT_UTF8

        val encrypted = Blowfish.encryptCBC(text.toByteArray(Charsets.UTF_8), key, iv, Padding.SCHEME.PKCS5)
        val decrypted = Blowfish.decryptCBC(encrypted, key, iv, Padding.SCHEME.PKCS5)

        assertArrayEquals(text.toByteArray(Charsets.UTF_8), decrypted)
    }

    @Test
    fun `throws on invalid key sizes`() {
        val plain = ByteArray(8)

        INVALID_KEY_SIZES.forEach { size ->
            assertThrows(IllegalArgumentException::class.java) {
                Blowfish.encryptECB(plain, ByteArray(size))
            }
        }
    }

    @Test
    fun `throws on non-block-aligned plaintext without padding`() {
        val key = Utils.randomBytes(16)
        assertThrows(IllegalArgumentException::class.java) {
            Blowfish.encryptECB(ByteArray(7), key) // Not multiple of 8 bytes
        }
    }

    @Test
    fun `throws on wrong IV size`() {
        val key = Utils.randomBytes(16)
        val plain = ByteArray(8)

        assertThrows(IllegalArgumentException::class.java) {
            Blowfish.encryptCBC(plain, key, ByteArray(4)) // IV must be 8 bytes
        }
    }
}