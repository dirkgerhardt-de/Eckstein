package com.hekeki.eckstein.blockcipher

import com.hekeki.eckstein.utils.Utils
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

class BlowfishTest {

    private val keySizes = listOf(4, 8, 16, 32, 56)

    @Test
    fun `ECB matches javax crypto reference for various key sizes`() {
        for (keySize in keySizes) {
            val key = Utils.randomBytes(keySize)
            val plain = Utils.randomBytes(32) // 4 blocks of 8 bytes

            val cipher = Cipher.getInstance("Blowfish/ECB/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "Blowfish"))
            val expected = cipher.doFinal(plain)

            val actual = Blowfish.encryptECB(plain, key)
            assertArrayEquals(expected, actual, "ECB encrypt mismatch for key size $keySize")

            val actualPlain = Blowfish.decryptECB(actual, key)
            assertArrayEquals(plain, actualPlain, "ECB decrypt mismatch for key size $keySize")
        }
    }

    @Test
    fun `ECB with PKCS5 padding matches javax crypto PKCS5Padding`() {
        val key = Utils.randomBytes(16)
        val plain = "Not block aligned!".toByteArray() // not multiple of 8

        val cipher = Cipher.getInstance("Blowfish/ECB/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "Blowfish"))
        val expected = cipher.doFinal(plain)

        val actual = Blowfish.encryptECB(plain, key, Padding.SCHEME.PKCS5)
        assertArrayEquals(expected, actual, "ECB+PKCS5 encrypt mismatch")

        val actualPlain = Blowfish.decryptECB(actual, key, Padding.SCHEME.PKCS5)
        assertArrayEquals(plain, actualPlain, "ECB+PKCS5 decrypt mismatch")
    }

    @Test
    fun `CBC matches javax crypto reference`() {
        for (keySize in keySizes) {
            val key = Utils.randomBytes(keySize)
            val iv = Utils.randomBytes(8)
            val plain = Utils.randomBytes(40) // 5 blocks

            val cipher = Cipher.getInstance("Blowfish/CBC/NoPadding")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "Blowfish"), IvParameterSpec(iv))
            val expected = cipher.doFinal(plain)

            val actual = Blowfish.encryptCBC(plain, key, iv)
            assertArrayEquals(expected, actual, "CBC encrypt mismatch for key size $keySize")

            val actualPlain = Blowfish.decryptCBC(actual, key, iv)
            assertArrayEquals(plain, actualPlain, "CBC decrypt mismatch for key size $keySize")
        }
    }

    @Test
    fun `CBC with PKCS5 padding matches javax crypto PKCS5Padding`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(8)
        val plain = "CBC test data, not block aligned".toByteArray()

        val cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "Blowfish"), IvParameterSpec(iv))
        val expected = cipher.doFinal(plain)

        val actual = Blowfish.encryptCBC(plain, key, iv, Padding.SCHEME.PKCS5)
        assertArrayEquals(expected, actual, "CBC+PKCS5 encrypt mismatch")

        val actualPlain = Blowfish.decryptCBC(actual, key, iv, Padding.SCHEME.PKCS5)
        assertArrayEquals(plain, actualPlain, "CBC+PKCS5 decrypt mismatch")
    }

    @Test
    fun `CBC roundtrip works with real UTF-8 text`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(8)
        val text = "Hällo Wörld! üöä ß 12345 - this needs padding."

        val encrypted = Blowfish.encryptCBC(text.toByteArray(Charsets.UTF_8), key, iv, Padding.SCHEME.PKCS5)
        val decrypted = Blowfish.decryptCBC(encrypted, key, iv, Padding.SCHEME.PKCS5)

        assertArrayEquals(text.toByteArray(Charsets.UTF_8), decrypted)
    }

    @Test
    fun `invalid key size throws`() {
        val plain = ByteArray(8)
        assertThrows(IllegalArgumentException::class.java) {
            Blowfish.encryptECB(plain, ByteArray(3))
        }
        assertThrows(IllegalArgumentException::class.java) {
            Blowfish.encryptECB(plain, ByteArray(57))
        }
        assertThrows(IllegalArgumentException::class.java) {
            Blowfish.encryptECB(plain, ByteArray(5)) // not multiple of 4
        }
    }

    @Test
    fun `non block aligned plaintext without padding throws`() {
        val key = Utils.randomBytes(16)
        assertThrows(IllegalArgumentException::class.java) {
            Blowfish.encryptECB(ByteArray(7), key)
        }
    }

    @Test
    fun `wrong iv size throws`() {
        val key = Utils.randomBytes(16)
        val plain = ByteArray(8)
        assertThrows(IllegalArgumentException::class.java) {
            Blowfish.encryptCBC(plain, key, ByteArray(4))
        }
    }
}

