/**
 * SerpentTest - Class to test encryption and decryption with Serpent
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
import org.bouncycastle.crypto.engines.SerpentEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class SerpentTest {

    companion object {

        private const val PLAINTEXT_DE = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
        private const val PLAINTEXT_EN = "Not block aligned data!!"
        private const val PLAINTEXT_UTF8 = "Hällo Wörld! üöä ß 12345 - this needs padding."

        private val VALID_KEY_SIZES = listOf(16, 24, 32)
        private val INVALID_KEY_SIZES = listOf(3, 20) // too small, invalid AES-like size

        private const val BLOCK_SIZE = 16

        /** Known-answer test vectors: plain / key / expected ciphertext (all hex). */
        private val ECB_VECTORS = listOf(
            Triple("00000000000000000000000000000000", "80000000000000000000000000000000", "264e5481eff42a4606abda06c0bfda3d"),
            Triple("00112233445566778899AABBCCDDEEFF", "000102030405060708090A0B0C0D0E0F", "563e2cf8740a27c164804560391e9b27"),
            Triple("00000000000000000000000000000000", "800000000000000000000000000000000000000000000000", "9e274ead9b737bb21efcfca548602689"),
            Triple("E0208BE278E21420C4B1B9747788A954", "2BD6459F82C5B300952C49104881FF482BD6459F82C5B300", "ea024714ad5c4d84ea024714ad5c4d84"),
            Triple("00000000000000000000000000000000", "8000000000000000000000000000000000000000000000000000000000000000", "a223aa1288463c0e2be38ebd825616c0"),
            Triple("677C8DFAA08071743FD2B415D1B28AF2", "2BD6459F82C5B300952C49104881FF482BD6459F82C5B300952C49104881FF48", "ea024714ad5c4d84ea024714ad5c4d84")
        )

        /** Expected ciphertext for CBC mode, indexed by key size (German plaintext, fixed IV). */
        private val CBC_VECTOR_BY_KEY_SIZE = mapOf(
            16 to "a084d0281bc8ac4b3e9d027327afef79ded7d0dbde6dee3a2399e17b920b2f34386109c9cedbb29b8f06393202003579e0b5548813457c2e289bcc75bd14b1a2b02c07e61f4f9e05d46f77a4e103af90",
            24 to "3e893cb66b78d37095e5e6af63e6b9a2c3f15e2ad16de15ea469f8bc144f69bfd9105b6e2b4b8b785a4e3836e5b8d8e430643a71fb89996c2cf1308c14088c3cb1aebb6eb67c42aff1255a2625ffb51e",
            32 to "8293653ab23bf075ed29111a482096addddc78ad93af385df0fd343f631739cdb3f8cf46cf6cbc99997ac4f44ac9b2db16f72d1221db959283f1ab761d627cd4780134afe17801e902c6ceef27cdd282"
        )

        private fun createKey(size: Int): ByteArray = ByteArray(size) { i -> (i + 1).toByte() }
        private fun createIv(): ByteArray = ByteArray(BLOCK_SIZE) { i -> (i + 1).toByte() }
    }

    @Test
    fun `standard test vectors ECB`() {
        ECB_VECTORS.forEachIndexed { i, (plain, key, expected) ->
            assertEquals(expected, Hex.encode(Serpent.encryptECB(Hex.toByteArray(plain), Hex.toByteArray(key))),
                "ECB encrypt mismatch in vector #$i")
            assertEquals(plain.lowercase(), Hex.encode(Serpent.decryptECB(Hex.toByteArray(expected), Hex.toByteArray(key))),
                "ECB decrypt mismatch in vector #$i")
        }
    }

    @Test
    fun `standard test vectors CBC`() {
        val iv = createIv()

        ECB_VECTORS.forEachIndexed { i, (plain, key, _) ->
            val encrypted = Hex.encode(Serpent.encryptCBC(Hex.toByteArray(plain), Hex.toByteArray(key), iv))
            assertEquals(plain.lowercase(), Hex.encode(Serpent.decryptCBC(Hex.toByteArray(encrypted), Hex.toByteArray(key), iv)),
                "CBC roundtrip mismatch in vector #$i")
        }
    }

    @Test
    fun `deterministic ECB encryption for all key sizes`() {
        val plain = PLAINTEXT_DE.toByteArray()

        VALID_KEY_SIZES.forEach { size ->
            val expected = when (size) {
                16 -> "c5e01c86f1bd5ce22b1e1874d5b5711a5cec3eac4de6e85bcf175d4e13a0dff2156e141c35a0cb59535d5079c160b65a82bb1008849031e26ac70fdb5343ada310e63daf15d229c25aa91870c869caf7"
                24 -> "dc89e697db514daa303ed9f4bd70cf32416dd5013b18458ed5b350451e8f6bcfd428071e13f4d7e8042ece6ac640cd0ed6ca4115d94ed9528ab91f0e9192244feac70b970d9acc2b88040a1ae3124964"
                32 -> "7b09d46d4eede733fb6f0d946bd8938ee424004d3c5badbed2958ddb79c5af543adb387f1c05227e1c7569a5fc97f86e16541de08859aac77f61108cf96cfdd4f16e41d9f2a3a59fc1becfddd8219e60"
                else -> throw IllegalArgumentException("Unhandled key size $size")
            }
            assertEquals(expected, Hex.encode(Serpent.encryptECB(plain, createKey(size), Padding.SCHEME.PKCS7)),
                "Deterministic ECB mismatch for key size ${size * 8} bits")
        }
    }

    @Test
    fun `deterministic CBC encryption for all key sizes`() {
        val plain = PLAINTEXT_DE.toByteArray()
        val iv = createIv()

        VALID_KEY_SIZES.forEach { size ->
            val expected = CBC_VECTOR_BY_KEY_SIZE.getValue(size)
            assertEquals(expected, Hex.encode(Serpent.encryptCBC(plain, createKey(size), iv, Padding.SCHEME.PKCS7)),
                "Deterministic CBC mismatch for key size ${size * 8} bits")
        }
    }

    @Test
    fun `encrypt and decrypt roundtrip with ECB mode`() {
        val plain = PLAINTEXT_DE.toByteArray()

        VALID_KEY_SIZES.forEach { size ->
            val key = Utils.randomBytes(size)
            val encrypted = Serpent.encryptECB(plain, key, Padding.SCHEME.PKCS7)
            assertArrayEquals(plain, Serpent.decryptECB(encrypted, key, Padding.SCHEME.PKCS7),
                "ECB roundtrip failed for key size ${size * 8} bits")
        }
    }

    @Test
    fun `encrypt and decrypt roundtrip with CBC mode`() {
        val plain = PLAINTEXT_DE.toByteArray()
        val iv = createIv()

        VALID_KEY_SIZES.forEach { size ->
            val key = Utils.randomBytes(size)
            val encrypted = Serpent.encryptCBC(plain, key, iv, Padding.SCHEME.PKCS7)
            assertArrayEquals(plain, Serpent.decryptCBC(encrypted, key, iv, Padding.SCHEME.PKCS7),
                "CBC roundtrip failed for key size ${size * 8} bits")
        }
    }

    @Test
    fun `ECB matches BouncyCastle reference for all key sizes`() {
        for (keySize in VALID_KEY_SIZES) {
            val key = Utils.randomBytes(keySize)
            val plain = Utils.randomBytes(48) // 3 blocks of 16 bytes

            val expected = bcProcess(BufferedBlockCipher(SerpentEngine()), true, KeyParameter(key), plain)
            val actual = Serpent.encryptECB(plain, key)
            assertArrayEquals(expected, actual, "ECB encrypt mismatch for key size ${keySize * 8} bits")

            val actualPlain = Serpent.decryptECB(actual, key)
            assertArrayEquals(plain, actualPlain, "ECB decrypt mismatch (roundtrip) for key size ${keySize * 8} bits")

            val bcDecrypted = bcProcess(BufferedBlockCipher(SerpentEngine()), false, KeyParameter(key), actual)
            assertArrayEquals(plain, bcDecrypted, "ECB decrypt mismatch against BC for key size ${keySize * 8} bits")
        }
    }

    @Test
    fun `CBC matches BouncyCastle reference for all key sizes`() {
        for (keySize in VALID_KEY_SIZES) {
            val key = Utils.randomBytes(keySize)
            val iv = Utils.randomBytes(BLOCK_SIZE)
            val plain = Utils.randomBytes(64) // 4 blocks

            val expected = bcProcess(BufferedBlockCipher(CBCBlockCipher(SerpentEngine())), true, ParametersWithIV(KeyParameter(key), iv), plain)
            val actual = Serpent.encryptCBC(plain, key, iv)
            assertArrayEquals(expected, actual, "CBC encrypt mismatch for key size ${keySize * 8} bits")

            val actualPlain = Serpent.decryptCBC(actual, key, iv)
            assertArrayEquals(plain, actualPlain, "CBC decrypt mismatch (roundtrip) for key size ${keySize * 8} bits")

            val bcDecrypted = bcProcess(BufferedBlockCipher(CBCBlockCipher(SerpentEngine())), false, ParametersWithIV(KeyParameter(key), iv), actual)
            assertArrayEquals(plain, bcDecrypted, "CBC decrypt mismatch against BC for key size ${keySize * 8} bits")
        }
    }

    @Test
    fun `CBC with PKCS7 padding matches BouncyCastle reference`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(BLOCK_SIZE)
        val plain = "CBC padding test data, arbitrary length".toByteArray()

        val expected = bcProcess(PaddedBufferedBlockCipher(CBCBlockCipher(SerpentEngine())),
            true, ParametersWithIV(KeyParameter(key), iv), plain)
        val actual = Serpent.encryptCBC(plain, key, iv, Padding.SCHEME.PKCS7)
        assertArrayEquals(expected, actual, "CBC+PKCS7 encrypt mismatch")

        val actualPlain = Serpent.decryptCBC(actual, key, iv, Padding.SCHEME.PKCS7)
        assertArrayEquals(plain, actualPlain, "CBC+PKCS7 decrypt roundtrip mismatch")
    }

    @Test
    fun `ECB with PKCS7 padding roundtrip`() {
        val key = Utils.randomBytes(16)
        val plain = PLAINTEXT_EN.toByteArray()

        val encrypted = Serpent.encryptECB(plain, key, Padding.SCHEME.PKCS7)
        assertArrayEquals(plain, Serpent.decryptECB(encrypted, key, Padding.SCHEME.PKCS7),
            "ECB+PKCS7 roundtrip mismatch")
    }

    @Test
    fun `CBC roundtrip works with real UTF-8 text`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(BLOCK_SIZE)

        val encrypted = Serpent.encryptCBC(PLAINTEXT_UTF8.toByteArray(Charsets.UTF_8), key, iv, Padding.SCHEME.PKCS7)
        val decrypted = Serpent.decryptCBC(encrypted, key, iv, Padding.SCHEME.PKCS7)

        assertArrayEquals(PLAINTEXT_UTF8.toByteArray(Charsets.UTF_8), decrypted)
    }

    @Test
    fun `original plaintext array is not mutated by CBC encrypt`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(BLOCK_SIZE)
        val plain = Utils.randomBytes(32)
        val plainCopy = plain.copyOf()

        Serpent.encryptCBC(plain, key, iv)

        assertArrayEquals(plainCopy, plain, "Caller's plaintext array must not be mutated")
    }

    @Test
    fun `throws on invalid key sizes`() {
        val plain = ByteArray(BLOCK_SIZE)

        INVALID_KEY_SIZES.forEach { size ->
            assertThrows(IllegalArgumentException::class.java) {
                Serpent.encryptECB(plain, ByteArray(size))
            }
        }
    }

    @Test
    fun `throws on non-block-aligned plaintext without padding`() {
        val key = Utils.randomBytes(16)
        assertThrows(IllegalArgumentException::class.java) {
            Serpent.encryptECB(ByteArray(BLOCK_SIZE - 1), key)
        }
    }

    @Test
    fun `throws on wrong IV size`() {
        val key = Utils.randomBytes(16)
        val plain = ByteArray(BLOCK_SIZE)
        assertThrows(IllegalArgumentException::class.java) {
            Serpent.encryptCBC(plain, key, ByteArray(BLOCK_SIZE / 2))
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