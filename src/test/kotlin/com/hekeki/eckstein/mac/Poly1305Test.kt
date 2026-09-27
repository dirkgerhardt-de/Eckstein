package com.hekeki.eckstein.mac

import org.bouncycastle.crypto.macs.Poly1305 as BcPoly1305
import org.bouncycastle.crypto.params.KeyParameter
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.RepeatedTest
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class Poly1305Test {

    private val random = SecureRandom()

    @Test
    fun `RFC 8439 test vector`() {
        val key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        val message = "Cryptographic Forum Research Group".toByteArray()
        val expected = hex("a8061dc1305136c6c22b8baf0c0127a9")

        assertArrayEquals(expected, Poly1305.authenticate(message, key))
        assertTrue(Poly1305.verify(expected, key, message))
    }

    @RepeatedTest(20)
    fun `matches BouncyCastle reference implementation`() {
        val key = ByteArray(32).also { random.nextBytes(it) }
        val message = ByteArray(random.nextInt(300)).also { random.nextBytes(it) }

        assertArrayEquals(bcPoly1305(key, message), Poly1305.authenticate(message, key))
    }

    @Test
    fun `empty message`() {
        val key = ByteArray(32).also { random.nextBytes(it) }

        assertArrayEquals(bcPoly1305(key, ByteArray(0)), Poly1305.authenticate(ByteArray(0), key))
    }

    @Test
    fun `message exactly one block`() {
        val key = ByteArray(32).also { random.nextBytes(it) }
        val message = ByteArray(16).also { random.nextBytes(it) }

        assertArrayEquals(bcPoly1305(key, message), Poly1305.authenticate(message, key))
    }

    private fun bcPoly1305(key: ByteArray, message: ByteArray): ByteArray {
        // Poly1305 (without an underlying cipher) just needs a raw 32-byte one-time key.
        val mac = BcPoly1305()
        mac.init(KeyParameter(key))
        mac.update(message, 0, message.size)
        val out = ByteArray(mac.macSize)
        mac.doFinal(out, 0)
        return out
    }

    @Test
    fun `verify accepts correct mac and rejects tampered message or mac`() {
        val key = ByteArray(32).also { random.nextBytes(it) }
        val message = "some message to authenticate".toByteArray()
        val mac = Poly1305.authenticate(message, key)

        assertTrue(Poly1305.verify(mac, key, message))
        assertFalse(Poly1305.verify(mac, key, "some message to authenticatee".toByteArray()))

        val tamperedMac = mac.copyOf()
        tamperedMac[0] = (tamperedMac[0] + 1).toByte()
        assertFalse(Poly1305.verify(tamperedMac, key, message))
    }

    @Test
    fun `invalid key size throws`() {
        val message = "test".toByteArray()
        try {
            Poly1305.authenticate(message, ByteArray(31))
            throw AssertionError("expected IllegalArgumentException")
        } catch (e: IllegalArgumentException) {
            // expected
        }
    }

    private fun hex(s: String): ByteArray {
        val clean = if (s.length % 2 != 0) "0$s" else s
        return ByteArray(clean.length / 2) { i ->
            clean.substring(i * 2, i * 2 + 2).toInt(16).toByte()
        }
    }
}

