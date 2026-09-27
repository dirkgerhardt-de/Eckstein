package com.hekeki.eckstein.mac

import org.bouncycastle.crypto.macs.Poly1305 as BcPoly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.RepeatedTest
import org.junit.jupiter.api.Test
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.SecretKeySpec

class Poly1305AESTest {

    private val random = SecureRandom()

    /**
     * Independent reference implementation of Poly1305-AES:
     *  - s = AES_k(nonce) via the JDK's own AES/ECB/NoPadding (NOT our AES.kt)
     *  - tag = Poly1305(message, r || s) via BouncyCastle's Poly1305
     * This cross-checks BOTH halves of Poly1305AES.kt against implementations
     * that are entirely independent of this project's own AES/Poly1305 code.
     */
    private fun referenceTag(message: ByteArray, nonce: ByteArray, key: ByteArray): ByteArray {
        val r = key.copyOfRange(0, 16)
        val aesKey = key.copyOfRange(16, 32)

        val cipher = Cipher.getInstance("AES/ECB/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(aesKey, "AES"))
        val s = cipher.doFinal(nonce)

        val mac = BcPoly1305()
        mac.init(KeyParameter(r + s))
        mac.update(message, 0, message.size)
        val out = ByteArray(mac.macSize)
        mac.doFinal(out, 0)
        return out
    }

    @RepeatedTest(25)
    fun `matches independent JCE plus BouncyCastle reference`() {
        val key = ByteArray(32).also { random.nextBytes(it) }
        val nonce = ByteArray(16).also { random.nextBytes(it) }
        val message = ByteArray(random.nextInt(300)).also { random.nextBytes(it) }

        val expected = referenceTag(message, nonce, key)
        assertArrayEquals(expected, Poly1305AES.authenticate(message, nonce, key))
    }

    @Test
    fun `empty message`() {
        val key = ByteArray(32).also { random.nextBytes(it) }
        val nonce = ByteArray(16).also { random.nextBytes(it) }

        val expected = referenceTag(ByteArray(0), nonce, key)
        assertArrayEquals(expected, Poly1305AES.authenticate(ByteArray(0), nonce, key))
    }

    @Test
    fun `different nonce yields different tag for same message and key`() {
        val key = ByteArray(32).also { random.nextBytes(it) }
        val message = "same message".toByteArray()
        val nonce1 = ByteArray(16).also { random.nextBytes(it) }
        val nonce2 = ByteArray(16).also { random.nextBytes(it) }

        val tag1 = Poly1305AES.authenticate(message, nonce1, key)
        val tag2 = Poly1305AES.authenticate(message, nonce2, key)

        assertFalse(tag1.contentEquals(tag2))
    }

    @Test
    fun `verify accepts correct mac and rejects tampering`() {
        val key = ByteArray(32).also { random.nextBytes(it) }
        val nonce = ByteArray(16).also { random.nextBytes(it) }
        val message = "authenticate me".toByteArray()

        val mac = Poly1305AES.authenticate(message, nonce, key)
        assertTrue(Poly1305AES.verify(mac, message, nonce, key))

        assertFalse(Poly1305AES.verify(mac, "authenticate mee".toByteArray(), nonce, key))

        val wrongNonce = nonce.copyOf()
        wrongNonce[0] = (wrongNonce[0] + 1).toByte()
        assertFalse(Poly1305AES.verify(mac, message, wrongNonce, key))

        val tamperedMac = mac.copyOf()
        tamperedMac[0] = (tamperedMac[0] + 1).toByte()
        assertFalse(Poly1305AES.verify(tamperedMac, message, nonce, key))
    }

    @Test
    fun `invalid key or nonce size throws`() {
        val message = "test".toByteArray()
        val validKey = ByteArray(32)
        val validNonce = ByteArray(16)

        assertThrows(IllegalArgumentException::class.java) {
            Poly1305AES.authenticate(message, validNonce, ByteArray(31))
        }
        assertThrows(IllegalArgumentException::class.java) {
            Poly1305AES.authenticate(message, ByteArray(15), validKey)
        }
    }
}

