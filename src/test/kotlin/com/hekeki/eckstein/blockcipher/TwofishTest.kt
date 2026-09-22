/**
 * TwofishTest - Class to test encryption and decryption with Twofish
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
import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.CipherParameters
import org.bouncycastle.crypto.engines.TwofishEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class TwofishTest {

    companion object {

        private const val PLAINTEXT_DE = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
        private const val PLAINTEXT_EN = "Not block aligned data!!"
        private const val PLAINTEXT_UTF8 = "Hällo Wörld! üöä ß 12345 - this needs padding."

        private val VALID_KEY_SIZES = listOf(16, 24, 32) // sizes usable with encrypt/decrypt API
        private val CHECK_KEY_SIZES = listOf(8, 16, 24, 32) // sizes accepted by checkKey
        private val INVALID_KEY_SIZES = listOf(7, 20, 33) // too small, not multiple of 8, too large

        private const val BLOCK_SIZE = 16

        /** Official Twofish test vectors: plain / key / expected ciphertext (all hex). */
        private val ECB_VECTORS = listOf(
            Triple("816D5BD0FAE35342BF2A7412C246F752", "6363977DE839486297E661C6C9D668EB", "5449eca008ff5921155f598af4ced4d0"),
            Triple("3AF6F7CE5BD35EF18BEC6FA787AB506B", "D1079B789F666649B6BD7D1629F1F77E7AFF7A70CA2FF28A", "ae8109bfda85c1f2c5038b34ed691bff"),
            Triple("3059D6D61753B958D92F4781C8640E58", "6CB4561C40BF0A9705931CB6D408E7FA90AFE91BB288544F2C32DC239B2635E6", "e69465770505d7f80ef68ca38ab3a3d6")
        )

        /** Expected ECB ciphertext for the German plaintext, indexed by key size (hex). */
        private val ECB_VECTOR_BY_KEY_SIZE = mapOf(
            16 to "e762cda24a9aebede80e709a5e41dd2093a7f974fc93a553b777d053d1c58e34eefb534724c26bd914c30a6e7dcc38e98f4415e0b3cdc47b55cb60612380017f92f2fc3b2e49ba9d0d43267adcb14c97",
            24 to "41d1cfc7f0d3e33c959f34fda62863c0812c794d87f04c6c2077cd13c18131c50ae6e0890525ebc9140ec9f118c6f4d3e7a12361f3ab64a4fa15965b1633507d645c8362074bb259c59f40cf2e795948",
            32 to "cedfd97f116346c49373811e194d1a72496b16d1653f01ed23118721ddd8c2a059f9f1f56e94f94c7e6fa644490f17d2fbb6574168eed5c6e9ceddf37776db9b49bbc24754993ed2aca896cdfda8f398"
        )

        /** Expected CBC ciphertext for the German plaintext (fixed IV), indexed by key size (hex). */
        private val CBC_VECTOR_BY_KEY_SIZE = mapOf(
            16 to "f985b5e1709daaed363399739ded336bd8ce52688de081228d4a78988e4a77d30b6c67501e0cfdffd562437e7d997bf9064cb4f359530f690f758be5293a597d90ddba5a199e4523715e8c4cb91de236",
            24 to "11a96e351a9b3c63d995d350971e8f17cc1e2e0973c4ebe5830bd2bdd55fea5a1c7191f4fe226a3cfe386a7a7003269b08dd81140d78255f0f850c727f942667b727c1126180b7249196ec13ce34f2a2",
            32 to "a080b9f2f3d23a6d15ba0d88845bfbfb7655ddee03c239f3f4b8b0952e6aecb2b6ca79261abec23eb7ab12a27207317ae3f0f750716f665dd6b9e4434a12c8a169e33e2f78ba720613161a5a013e5085"
        )

        private fun createKey(size: Int): ByteArray = ByteArray(size) { i -> (i + 1).toByte() }
        private fun createIv(): ByteArray = ByteArray(BLOCK_SIZE) { i -> (i + 1).toByte() }
    }

    @Test
    fun `standard test vectors ECB`() {
        ECB_VECTORS.forEachIndexed { i, (plain, key, expected) ->
            assertEquals(expected, Hex.encode(Twofish.encryptECB(Hex.toByteArray(plain), Hex.toByteArray(key))),
                "ECB encrypt mismatch in vector #$i")
            assertEquals(plain.lowercase(), Hex.encode(Twofish.decryptECB(Hex.toByteArray(expected), Hex.toByteArray(key))),
                "ECB decrypt mismatch in vector #$i")
        }
    }

    @Test
    fun `deterministic ECB encryption for all key sizes`() {
        val plain = PLAINTEXT_DE.toByteArray()

        VALID_KEY_SIZES.forEach { size ->
            val expected = ECB_VECTOR_BY_KEY_SIZE.getValue(size)
            assertEquals(expected, Hex.encode(Twofish.encryptECB(plain, createKey(size), Padding.SCHEME.PKCS7)),
                "Deterministic ECB mismatch for key size ${size * 8} bits")
        }
    }

    @Test
    fun `deterministic CBC encryption for all key sizes`() {
        val plain = PLAINTEXT_DE.toByteArray()
        val iv = createIv()

        VALID_KEY_SIZES.forEach { size ->
            val expected = CBC_VECTOR_BY_KEY_SIZE.getValue(size)
            assertEquals(expected, Hex.encode(Twofish.encryptCBC(plain, createKey(size), iv, Padding.SCHEME.PKCS7)),
                "Deterministic CBC mismatch for key size ${size * 8} bits")
        }
    }

    @Test
    fun `encrypt and decrypt roundtrip with ECB mode`() {
        val plain = PLAINTEXT_DE.toByteArray()

        VALID_KEY_SIZES.forEach { size ->
            val key = Utils.randomBytes(size)
            val encrypted = Twofish.encryptECB(plain, key, Padding.SCHEME.PKCS7)
            assertArrayEquals(plain, Twofish.decryptECB(encrypted, key, Padding.SCHEME.PKCS7),
                "ECB roundtrip failed for key size ${size * 8} bits")
        }
    }

    @Test
    fun `encrypt and decrypt roundtrip with CBC mode`() {
        val plain = PLAINTEXT_DE.toByteArray()
        val iv = createIv()

        VALID_KEY_SIZES.forEach { size ->
            val key = Utils.randomBytes(size)
            val encrypted = Twofish.encryptCBC(plain, key, iv, Padding.SCHEME.PKCS7)
            assertArrayEquals(plain, Twofish.decryptCBC(encrypted, key, iv, Padding.SCHEME.PKCS7),
                "CBC roundtrip failed for key size ${size * 8} bits")
        }
    }

    @Test
    fun `ECB matches BouncyCastle reference for all key sizes`() {
        for (keySize in VALID_KEY_SIZES) {
            val key = Utils.randomBytes(keySize)
            val plain = Utils.randomBytes(48) // 3 blocks of 16 bytes

            val expected = bcProcess(BufferedBlockCipher(TwofishEngine()), true, KeyParameter(key), plain)
            val actual = Twofish.encryptECB(plain, key)
            assertArrayEquals(expected, actual, "ECB encrypt mismatch for key size ${keySize * 8} bits")

            val actualPlain = Twofish.decryptECB(actual, key)
            assertArrayEquals(plain, actualPlain, "ECB decrypt mismatch (roundtrip) for key size ${keySize * 8} bits")

            val bcDecrypted = bcProcess(BufferedBlockCipher(TwofishEngine()), false, KeyParameter(key), actual)
            assertArrayEquals(plain, bcDecrypted, "ECB decrypt mismatch against BC for key size ${keySize * 8} bits")
        }
    }

    @Test
    fun `CBC matches BouncyCastle reference for all key sizes`() {
        for (keySize in VALID_KEY_SIZES) {
            val key = Utils.randomBytes(keySize)
            val iv = Utils.randomBytes(BLOCK_SIZE)
            val plain = Utils.randomBytes(64) // 4 blocks

            val expected = bcProcess(BufferedBlockCipher(CBCBlockCipher(TwofishEngine())), true, ParametersWithIV(KeyParameter(key), iv), plain)
            val actual = Twofish.encryptCBC(plain, key, iv)
            assertArrayEquals(expected, actual, "CBC encrypt mismatch for key size ${keySize * 8} bits")

            val actualPlain = Twofish.decryptCBC(actual, key, iv)
            assertArrayEquals(plain, actualPlain, "CBC decrypt mismatch (roundtrip) for key size ${keySize * 8} bits")

            val bcDecrypted = bcProcess(BufferedBlockCipher(CBCBlockCipher(TwofishEngine())), false, ParametersWithIV(KeyParameter(key), iv), actual)
            assertArrayEquals(plain, bcDecrypted, "CBC decrypt mismatch against BC for key size ${keySize * 8} bits")
        }
    }

    @Test
    fun `CBC with PKCS7 padding matches BouncyCastle reference`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(BLOCK_SIZE)
        val plain = "CBC padding test data, arbitrary length".toByteArray()

        val expected = bcProcess(PaddedBufferedBlockCipher(CBCBlockCipher(TwofishEngine())),
            true, ParametersWithIV(KeyParameter(key), iv), plain)
        val actual = Twofish.encryptCBC(plain, key, iv, Padding.SCHEME.PKCS7)
        assertArrayEquals(expected, actual, "CBC+PKCS7 encrypt mismatch")

        val actualPlain = Twofish.decryptCBC(actual, key, iv, Padding.SCHEME.PKCS7)
        assertArrayEquals(plain, actualPlain, "CBC+PKCS7 decrypt roundtrip mismatch")
    }

    @Test
    fun `ECB with PKCS7 padding roundtrip`() {
        val key = Utils.randomBytes(16)
        val plain = PLAINTEXT_EN.toByteArray() // not multiple of 16

        val encrypted = Twofish.encryptECB(plain, key, Padding.SCHEME.PKCS7)
        assertArrayEquals(plain, Twofish.decryptECB(encrypted, key, Padding.SCHEME.PKCS7),
            "ECB+PKCS7 roundtrip mismatch")
    }

    @Test
    fun `CBC roundtrip works with real UTF-8 text`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(BLOCK_SIZE)

        val encrypted = Twofish.encryptCBC(PLAINTEXT_UTF8.toByteArray(Charsets.UTF_8), key, iv, Padding.SCHEME.PKCS7)
        val decrypted = Twofish.decryptCBC(encrypted, key, iv, Padding.SCHEME.PKCS7)

        assertArrayEquals(PLAINTEXT_UTF8.toByteArray(Charsets.UTF_8), decrypted)
    }

    @Test
    fun `original plaintext array is not mutated by CBC encrypt`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(BLOCK_SIZE)
        val plain = Utils.randomBytes(32)
        val plainCopy = plain.copyOf()

        Twofish.encryptCBC(plain, key, iv)

        assertArrayEquals(plainCopy, plain, "Caller's plaintext array must not be mutated")
    }

    @Test
    fun `checkKey accepts all valid key sizes`() {
        CHECK_KEY_SIZES.forEach { size ->
            Twofish.checkKey(Utils.randomBytes(size))
        }
    }

    @Test
    fun `throws on invalid key sizes`() {
        val plain = ByteArray(BLOCK_SIZE)

        INVALID_KEY_SIZES.forEach { size ->
            assertThrows(IllegalArgumentException::class.java) {
                Twofish.encryptECB(plain, ByteArray(size))
            }
        }
    }

    @Test
    fun `throws on non-block-aligned plaintext without padding`() {
        val key = Utils.randomBytes(16)
        assertThrows(IllegalArgumentException::class.java) {
            Twofish.encryptECB(ByteArray(BLOCK_SIZE - 1), key)
        }
    }

    @Test
    fun `throws on wrong IV size`() {
        val key = Utils.randomBytes(16)
        val plain = ByteArray(BLOCK_SIZE)
        assertThrows(IllegalArgumentException::class.java) {
            Twofish.encryptCBC(plain, key, ByteArray(BLOCK_SIZE / 2))
        }
    }

    private fun bcProcess(cipher: BufferedBlockCipher, forEncryption: Boolean, params: CipherParameters, data: ByteArray): ByteArray {
        cipher.init(forEncryption, params)
        val out = ByteArray(cipher.getOutputSize(data.size))
        var len = cipher.processBytes(data, 0, data.size, out, 0)
        len += cipher.doFinal(out, len)
        return out.copyOf(len)
    }
}