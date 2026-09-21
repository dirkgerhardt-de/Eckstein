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

import com.hekeki.eckstein.encoding.Base64
import com.hekeki.eckstein.encoding.Hex
import com.hekeki.eckstein.utils.Utils
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class AESTest {

    private val keySizes = listOf(16, 24, 32)

    @Test
    fun `encrypt ECB tests`() {
        val plain = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."

        val key128 = ByteArray(16) { i -> (i + 1).toByte() }
        assertEquals("EX9Bx5K388OQwq7FFTrQ2h/7QV1LXlhHvuBMhAlyb8Jrw/L1ZSxhxRbqhsIjbhJBdFcmgU9v4p8zEvEK41lylGHAsPEETReqkgtjH9lmHR0=",
            Base64.encode(AES.encryptECB(plain.toByteArray(), key128, Padding.SCHEME.PKCS7)))

        val key256 = ByteArray(32) { i -> (i + 1).toByte() }
        assertEquals("u5PoaqnYSGzB4F8NLZ/hiNj03nAsSmnMHeNSYNTYsoAxMu9vAIfCehhSrPsQ85NlY7HbzlKafYQi61DmUQ6OcAl/Rm7oRQUp839LAmDz8bw=",
            Base64.encode(AES.encryptECB(plain.toByteArray(), key256, Padding.SCHEME.PKCS7)))
    }

    @Test
    fun `decrypt ECB tests`() {

        val plain = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."

        val key128 = Utils.randomBytes(16)
        assertEquals(plain, String(AES.decryptECB(AES.encryptECB(plain.toByteArray(), key128, Padding.SCHEME.PKCS7), key128, Padding.SCHEME.PKCS7)))

        val key256 = Utils.randomBytes(32)
        assertEquals(plain, String(AES.decryptECB(AES.encryptECB(plain.toByteArray(), key256, Padding.SCHEME.PKCS7), key256, Padding.SCHEME.PKCS7)))
    }

    @Test
    fun `encrypt CBC tests`() {

        val plain = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
        val iv = ByteArray(16) { i -> (i + 1).toByte() }

        val key128 = ByteArray(16) { i -> (i + 1).toByte() }
        assertEquals("AAcOey3Dkx7fnWhTAOlYGTPNuMdHOcIKuV+jzjKq+gkJH3QtAFsBNF65MUr00bO50gd/QGMbVNUFNFg0c4UtFtbI0FpEbpuJ+deWpbuRryA=",
            Base64.encode(AES.encryptCBC(plain.toByteArray(), key128, iv, Padding.SCHEME.PKCS7)))

        val key256 = ByteArray(32) { i -> (i + 1).toByte() }
        assertEquals("GLmNf0fBrhhGh0h7YDAhEpuxkuG7K5whxuJM3nSFxEfbql/WwPpgCmc1h4+O4qbqLCHLVZKmQE/WK4B+B/TDj/eEATOAHuMJbIKAtvQU5SE=",
            Base64.encode(AES.encryptCBC(plain.toByteArray(), key256, iv, Padding.SCHEME.PKCS7)))
    }

    @Test
    fun `decrypt CBC tests`() {

        val plain = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
        val iv = Utils.randomBytes(16)

        val key128 = Utils.randomBytes(16)
        assertEquals(plain, String(AES.decryptCBC(AES.encryptCBC(plain.toByteArray(), key128, iv, Padding.SCHEME.PKCS7), key128, iv, Padding.SCHEME.PKCS7)))

        val key256 = Utils.randomBytes(32)
        assertEquals(plain, String(AES.decryptCBC(AES.encryptCBC(plain.toByteArray(), key256, iv, Padding.SCHEME.PKCS7), key256, iv, Padding.SCHEME.PKCS7)))
    }

    @Test
    fun `encrypt CTR tests`() {
        val plain = Hex.toByteArray("6bc1bee22e409f96e93d7e117393172a")
        val iv = Hex.toByteArray("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        val key128 = Hex.toByteArray("2b7e151628aed2a6abf7158809cf4f3c")
        assertEquals("874d6191b620e3261bef6864990db6ce", Hex.encode(AES.encryptCTR(plain, key128, iv)))

        val key192 = Hex.toByteArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
        assertEquals("1abc932417521ca24f2b0459fe7e6e0b", Hex.encode(AES.encryptCTR(plain, key192, iv)))

        val key256 = Hex.toByteArray("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4")
        assertEquals("601ec313775789a5b7a7f504bbf3d228", Hex.encode(AES.encryptCTR(plain, key256, iv)))
    }

    @Test
    fun `decrypt CTR tests`() {
        var ciphertext = Hex.toByteArray("874d6191b620e3261bef6864990db6ce")
        val iv = Hex.toByteArray("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff")

        val key128 = Hex.toByteArray("2b7e151628aed2a6abf7158809cf4f3c")
        assertEquals("6bc1bee22e409f96e93d7e117393172a", Hex.encode(AES.decryptCTR(ciphertext, key128, iv)))

        ciphertext = Hex.toByteArray("1abc932417521ca24f2b0459fe7e6e0b")
        val key192 = Hex.toByteArray("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b")
        assertEquals("6bc1bee22e409f96e93d7e117393172a", Hex.encode(AES.decryptCTR(ciphertext, key192, iv)))
    }

    @Test
    fun `encrypt decrypt CTR with padding`() {

        val plain = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
        val key128 = Utils.randomBytes(16)
        val nonce = Utils.randomBytes(16)

        assertEquals(plain, String(AES.decryptCTR(
            AES.encryptCTR(plain.toByteArray(), key128, nonce, Padding.SCHEME.PKCS7), key128, nonce, Padding.SCHEME.PKCS7)))

        val key192 = Utils.randomBytes(24)
        assertEquals(plain, String(AES.decryptCTR(
            AES.encryptCTR(plain.toByteArray(), key192, nonce, Padding.SCHEME.PKCS7), key192, nonce, Padding.SCHEME.PKCS7)))

        val key256 = Utils.randomBytes(32)
        assertEquals(plain, String(AES.decryptCTR(
            AES.encryptCTR(plain.toByteArray(), key256, nonce, Padding.SCHEME.PKCS7), key256, nonce, Padding.SCHEME.PKCS7)))
    }

    @Test
    fun `encrypt decrypt CTR without padding`() {

        val plain = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
        val key128 = Utils.randomBytes(16)
        val nonce = Utils.randomBytes(16)

        assertEquals(plain, String(AES.decryptCTR(
            AES.encryptCTR(plain.toByteArray(), key128, nonce), key128, nonce)))

        val key192 = Utils.randomBytes(24)
        assertEquals(plain, String(AES.decryptCTR(
            AES.encryptCTR(plain.toByteArray(), key192, nonce), key192, nonce)))

        val key256 = Utils.randomBytes(32)
        assertEquals(plain, String(AES.decryptCTR(
            AES.encryptCTR(plain.toByteArray(), key256, nonce), key256, nonce)))
    }

    @Test
    fun `CBC encrypt invalid IV size 1`() {
        assertThrows(IllegalArgumentException::class.java) {AES.encryptCBC(Utils.randomBytes(10), Utils.randomBytes(16), Utils.randomBytes(15))}
    }

    @Test
    fun `CBC encrypt invalid IV size 2`() {
        assertThrows(IllegalArgumentException::class.java) {AES.encryptCBC(Utils.randomBytes(10), Utils.randomBytes(16), Utils.randomBytes(17))}
    }

    @Test
    fun `CBC decrypt invalid IV size 1`() {
        assertThrows(IllegalArgumentException::class.java) {AES.decryptCBC(Utils.randomBytes(10), Utils.randomBytes(16), Utils.randomBytes(15))}
    }

    @Test
    fun `CBC decrypt invalid IV size 2`() {
        assertThrows(IllegalArgumentException::class.java) {AES.decryptCBC(Utils.randomBytes(10), Utils.randomBytes(16), Utils.randomBytes(17))}
    }

    @Test
    fun `CTR encrypt invalid IV size 1`() {
        assertThrows(IllegalArgumentException::class.java) {AES.encryptCTR(Utils.randomBytes(10), Utils.randomBytes(16), Utils.randomBytes(15))}
    }

    @Test
    fun `CTR encrypt invalid IV size 2`() {
        assertThrows(IllegalArgumentException::class.java) {AES.encryptCTR(Utils.randomBytes(10), Utils.randomBytes(16), Utils.randomBytes(17))}
    }

    @Test
    fun `CTR decrypt invalid IV size 1`() {
        assertThrows(IllegalArgumentException::class.java) {AES.decryptCTR(Utils.randomBytes(10), Utils.randomBytes(16), Utils.randomBytes(15))}
    }

    @Test
    fun `CTR decrypt invalid IV size 2`() {
        assertThrows(IllegalArgumentException::class.java) {AES.decryptCTR(Utils.randomBytes(10), Utils.randomBytes(16), Utils.randomBytes(17))}
    }

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

