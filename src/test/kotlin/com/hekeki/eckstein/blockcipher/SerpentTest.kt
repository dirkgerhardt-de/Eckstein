package com.hekeki.eckstein.blockcipher

import com.hekeki.eckstein.utils.Utils
import org.bouncycastle.crypto.BufferedBlockCipher
import org.bouncycastle.crypto.engines.SerpentEngine
import org.bouncycastle.crypto.modes.CBCBlockCipher
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.ParametersWithIV
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Test

class SerpentTest {

    private val keySizes = listOf(16, 24, 32)

    private fun bcEncryptEcbNoPadding(plain: ByteArray, key: ByteArray): ByteArray {
        val cipher = BufferedBlockCipher(SerpentEngine())
        cipher.init(true, KeyParameter(key))
        val out = ByteArray(cipher.getOutputSize(plain.size))
        var len = cipher.processBytes(plain, 0, plain.size, out, 0)
        len += cipher.doFinal(out, len)
        return out.copyOf(len)
    }

    private fun bcDecryptEcbNoPadding(cipherText: ByteArray, key: ByteArray): ByteArray {
        val cipher = BufferedBlockCipher(SerpentEngine())
        cipher.init(false, KeyParameter(key))
        val out = ByteArray(cipher.getOutputSize(cipherText.size))
        var len = cipher.processBytes(cipherText, 0, cipherText.size, out, 0)
        len += cipher.doFinal(out, len)
        return out.copyOf(len)
    }

    private fun bcEncryptCbcNoPadding(plain: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = BufferedBlockCipher(CBCBlockCipher(SerpentEngine()))
        cipher.init(true, ParametersWithIV(KeyParameter(key), iv))
        val out = ByteArray(cipher.getOutputSize(plain.size))
        var len = cipher.processBytes(plain, 0, plain.size, out, 0)
        len += cipher.doFinal(out, len)
        return out.copyOf(len)
    }

    private fun bcDecryptCbcNoPadding(cipherText: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = BufferedBlockCipher(CBCBlockCipher(SerpentEngine()))
        cipher.init(false, ParametersWithIV(KeyParameter(key), iv))
        val out = ByteArray(cipher.getOutputSize(cipherText.size))
        var len = cipher.processBytes(cipherText, 0, cipherText.size, out, 0)
        len += cipher.doFinal(out, len)
        return out.copyOf(len)
    }

    private fun bcEncryptCbcPkcs7(plain: ByteArray, key: ByteArray, iv: ByteArray): ByteArray {
        val cipher = PaddedBufferedBlockCipher(CBCBlockCipher(SerpentEngine()))
        cipher.init(true, ParametersWithIV(KeyParameter(key), iv))
        val out = ByteArray(cipher.getOutputSize(plain.size))
        var len = cipher.processBytes(plain, 0, plain.size, out, 0)
        len += cipher.doFinal(out, len)
        return out.copyOf(len)
    }

    @Test
    fun `ECB matches BouncyCastle reference for all key sizes`() {
        for (keySize in keySizes) {
            val key = Utils.randomBytes(keySize)
            val plain = Utils.randomBytes(48) // 3 blocks of 16 bytes

            val expected = bcEncryptEcbNoPadding(plain, key)
            val actual = Serpent.encryptECB(plain, key)
            assertArrayEquals(expected, actual, "ECB encrypt mismatch for key size $keySize")

            val actualPlain = Serpent.decryptECB(actual, key)
            assertArrayEquals(plain, actualPlain, "ECB decrypt mismatch (roundtrip) for key size $keySize")

            val bcDecrypted = bcDecryptEcbNoPadding(actual, key)
            assertArrayEquals(plain, bcDecrypted, "ECB decrypt mismatch against BC for key size $keySize")
        }
    }

    @Test
    fun `CBC matches BouncyCastle reference for all key sizes`() {
        for (keySize in keySizes) {
            val key = Utils.randomBytes(keySize)
            val iv = Utils.randomBytes(16)
            val plain = Utils.randomBytes(64) // 4 blocks

            val expected = bcEncryptCbcNoPadding(plain, key, iv)
            val actual = Serpent.encryptCBC(plain, key, iv)
            assertArrayEquals(expected, actual, "CBC encrypt mismatch for key size $keySize")

            val actualPlain = Serpent.decryptCBC(actual, key, iv)
            assertArrayEquals(plain, actualPlain, "CBC decrypt mismatch (roundtrip) for key size $keySize")

            val bcDecrypted = bcDecryptCbcNoPadding(actual, key, iv)
            assertArrayEquals(plain, bcDecrypted, "CBC decrypt mismatch against BC for key size $keySize")
        }
    }

    @Test
    fun `ECB with PKCS7 padding matches roundtrip`() {
        val key = Utils.randomBytes(16)
        val plain = "Not block aligned data!!".toByteArray()

        val actual = Serpent.encryptECB(plain, key, Padding.SCHEME.PKCS7)
        val actualPlain = Serpent.decryptECB(actual, key, Padding.SCHEME.PKCS7)
        assertArrayEquals(plain, actualPlain, "ECB+PKCS7 roundtrip mismatch")
    }

    @Test
    fun `CBC with PKCS7 padding matches BouncyCastle reference`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(16)
        val plain = "CBC padding test data, arbitrary length".toByteArray()

        val expected = bcEncryptCbcPkcs7(plain, key, iv)
        val actual = Serpent.encryptCBC(plain, key, iv, Padding.SCHEME.PKCS7)
        assertArrayEquals(expected, actual, "CBC+PKCS7 encrypt mismatch")

        val actualPlain = Serpent.decryptCBC(actual, key, iv, Padding.SCHEME.PKCS7)
        assertArrayEquals(plain, actualPlain, "CBC+PKCS7 decrypt roundtrip mismatch")
    }

    @Test
    fun `CBC roundtrip works with real UTF-8 text`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(16)
        val text = "Hällo Wörld! üöä ß 12345 - this needs padding."

        val encrypted = Serpent.encryptCBC(text.toByteArray(Charsets.UTF_8), key, iv, Padding.SCHEME.PKCS7)
        val decrypted = Serpent.decryptCBC(encrypted, key, iv, Padding.SCHEME.PKCS7)

        assertArrayEquals(text.toByteArray(Charsets.UTF_8), decrypted)
    }

    @Test
    fun `original plaintext array is not mutated by CBC encrypt`() {
        val key = Utils.randomBytes(16)
        val iv = Utils.randomBytes(16)
        val plain = Utils.randomBytes(32)
        val plainCopy = plain.copyOf()

        Serpent.encryptCBC(plain, key, iv)

        assertArrayEquals(plainCopy, plain, "Caller's plaintext array must not be mutated")
    }

    @Test
    fun `invalid key size throws`() {
        val plain = ByteArray(16)
        assertThrows(IllegalArgumentException::class.java) {
            Serpent.encryptECB(plain, ByteArray(20))
        }
    }

    @Test
    fun `non block aligned plaintext without padding throws`() {
        val key = Utils.randomBytes(16)
        assertThrows(IllegalArgumentException::class.java) {
            Serpent.encryptECB(ByteArray(15), key)
        }
    }

    @Test
    fun `wrong iv size throws`() {
        val key = Utils.randomBytes(16)
        val plain = ByteArray(16)
        assertThrows(IllegalArgumentException::class.java) {
            Serpent.encryptCBC(plain, key, ByteArray(8))
        }
    }
}

