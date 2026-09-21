/**
 * AES - Encryption and decryption with Advanced Encryption Standard
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

import com.hekeki.eckstein.utils.Utils
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESTest {

    private val keySizes = listOf(16, 24, 32)

    @Test
    fun `ECB matches javax crypto reference for all key sizes`() {
        for (keySize in keySizes) {
            val key = Utils.randomBytes(keySize)
            val plain = Utils.randomBytes(64) // 4 blocks, multiple of 16

            val cipher = Cipher.getInstance("AES/ECB/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
            val expectedCipherText = cipher.doFinal(plain)

            val actualCipherText = AES.encryptECB(plain, key)
            assertArrayEquals(expectedCipherText, actualCipherText, "ECB encrypt mismatch for key size $keySize")

            val actualPlain = AES.decryptECB(actualCipherText, key)
            assertArrayEquals(plain, actualPlain, "ECB decrypt mismatch for key size $keySize")
        }
    }

    @Test
    fun `ECB with PKCS7 padding matches javax crypto PKCS5Padding`() {
        for (keySize in keySizes) {
            val key = Utils.randomBytes(keySize)
            val plain = "This is not block aligned!!".toByteArray() // not multiple of 16

            val cipher = Cipher.getInstance("AES/ECB/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"))
            val expectedCipherText = cipher.doFinal(plain)

            val actualCipherText = AES.encryptECB(plain, key, Padding.SCHEME.PKCS7)
            assertArrayEquals(expectedCipherText, actualCipherText, "ECB+PKCS7 encrypt mismatch for key size $keySize")

            val actualPlain = AES.decryptECB(actualCipherText, key, Padding.SCHEME.PKCS7)
            assertArrayEquals(plain, actualPlain, "ECB+PKCS7 decrypt mismatch for key size $keySize")
        }
    }

    @Test
    fun `CBC matches javax crypto reference for all key sizes`() {
        for (keySize in keySizes) {
            val key = Utils.randomBytes(keySize)
            val iv = Utils.randomBytes(16)
            val plain = Utils.randomBytes(80) // 5 blocks

            val cipher = Cipher.getInstance("AES/CBC/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            val expectedCipherText = cipher.doFinal(plain)

            val actualCipherText = AES.encryptCBC(plain, key, iv)
            assertArrayEquals(expectedCipherText, actualCipherText, "CBC encrypt mismatch for key size $keySize")

            val actualPlain = AES.decryptCBC(actualCipherText, key, iv)
            assertArrayEquals(plain, actualPlain, "CBC decrypt mismatch for key size $keySize")
        }
    }

    @Test
    fun `CBC with PKCS7 padding matches javax crypto PKCS5Padding`() {
        for (keySize in keySizes) {
            val key = Utils.randomBytes(keySize)
            val iv = Utils.randomBytes(16)
            val plain = "Not block aligned CBC test data".toByteArray().copyOf(37) // arbitrary length

            val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
            val expectedCipherText = cipher.doFinal(plain)

            val actualCipherText = AES.encryptCBC(plain, key, iv, Padding.SCHEME.PKCS7)
            assertArrayEquals(expectedCipherText, actualCipherText, "CBC+PKCS7 encrypt mismatch for key size $keySize")

            val actualPlain = AES.decryptCBC(actualCipherText, key, iv, Padding.SCHEME.PKCS7)
            assertArrayEquals(plain, actualPlain, "CBC+PKCS7 decrypt mismatch for key size $keySize")
        }
    }

    @Test
    fun `CTR matches javax crypto reference for all key sizes and arbitrary lengths`() {
        for (keySize in keySizes) {
            for (len in listOf(1, 15, 16, 17, 32, 63, 100)) {
                val key = Utils.randomBytes(keySize)
                val nonce = Utils.randomBytes(16)
                val plain = Utils.randomBytes(len)

                val cipher = Cipher.getInstance("AES/CTR/NoPadding")
                cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(nonce))
                val expectedCipherText = cipher.doFinal(plain)

                val actualCipherText = AES.encryptCTR(plain, key, nonce)
                assertArrayEquals(expectedCipherText, actualCipherText, "CTR encrypt mismatch for key size $keySize len $len")

                val actualPlain = AES.decryptCTR(actualCipherText, key, nonce)
                assertArrayEquals(plain, actualPlain, "CTR decrypt mismatch for key size $keySize len $len")
            }
        }
    }

    @Test
    fun `CBC roundtrip works with real UTF-8 text`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(16)
        val text = "Hällo Wörld! üöä ß 12345 - this needs padding."

        val encrypted = AES.encryptCBC(text.toByteArray(Charsets.UTF_8), key, iv, Padding.SCHEME.PKCS7)
        val decrypted = AES.decryptCBC(encrypted, key, iv, Padding.SCHEME.PKCS7)

        assertArrayEquals(text.toByteArray(Charsets.UTF_8), decrypted)
    }

    @Test
    fun `invalid key size throws`() {
        val plain = ByteArray(16)
        assertThrows(IllegalArgumentException::class.java) {
            AES.encryptECB(plain, ByteArray(20))
        }
    }

    @Test
    fun `non block aligned plaintext without padding throws`() {
        val key = Utils.randomBytes(16)
        assertThrows(IllegalArgumentException::class.java) {
            AES.encryptECB(ByteArray(15), key)
        }
    }

    @Test
    fun `wrong iv size throws`() {
        val key = Utils.randomBytes(16)
        val plain = ByteArray(16)
        assertThrows(IllegalArgumentException::class.java) {
            AES.encryptCBC(plain, key, ByteArray(8))
        }
    }
}

