/**
 * ChaCha20Poly1305 - AEAD construction (RFC 8439, section 2.8)
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
package com.hekeki.eckstein.aead

import com.hekeki.eckstein.encoding.Hex
import com.hekeki.eckstein.utils.Utils
import org.bouncycastle.crypto.InvalidCipherTextException
import org.bouncycastle.crypto.modes.ChaCha20Poly1305 as BcChaCha20Poly1305
import org.bouncycastle.crypto.params.AEADParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class ChaCha20Poly1305Test {

    @Test
    fun `RFC 8439 section 2_8_2 test vector`() {
        val key = Hex.toByteArray("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
        val nonce = Hex.toByteArray("070000004041424344454647")
        val aad = Hex.toByteArray("50515253c0c1c2c3c4c5c6c7")
        val plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only " +
            "one tip for the future, sunscreen would be it."
        val expectedCipher = Hex.toByteArray(
            "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d" +
                "63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b" +
                "3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d" +
                "7bc3ff4def08e4b7a9de576d26586cec64b6116"
        )
        val expectedTag = Hex.toByteArray("1ae10b594f09e26a7e902ecbd0600691")

        val result = ChaCha20Poly1305.encrypt(key, nonce, plaintext.toByteArray(), aad)
        val actualCipher = result.copyOfRange(0, result.size - ChaCha20Poly1305.TAG_SIZE)
        val actualTag = result.copyOfRange(result.size - ChaCha20Poly1305.TAG_SIZE, result.size)

        assertArrayEquals(expectedCipher, actualCipher, "ciphertext mismatch")
        assertArrayEquals(expectedTag, actualTag, "tag mismatch")

        val decrypted = ChaCha20Poly1305.decrypt(key, nonce, result, aad)
        assertArrayEquals(plaintext.toByteArray(), decrypted)
    }

    @Test
    fun `encrypt then decrypt roundtrip with and without AAD`() {
        val key = Utils.randomBytes(ChaCha20Poly1305.KEY_SIZE)
        val nonce = ChaCha20Poly1305.nonce()
        val plain = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an.".toByteArray()

        val noAad = ChaCha20Poly1305.encrypt(key, nonce, plain)
        assertArrayEquals(plain, ChaCha20Poly1305.decrypt(key, nonce, noAad))

        val aad = "additional authenticated data".toByteArray()
        val withAad = ChaCha20Poly1305.encrypt(key, nonce, plain, aad)
        assertArrayEquals(plain, ChaCha20Poly1305.decrypt(key, nonce, withAad, aad))
    }

    @Test
    fun `matches BouncyCastle ChaCha20Poly1305 reference for arbitrary lengths and AAD`() {
        for (len in listOf(0, 1, 15, 16, 17, 63, 64, 65, 200)) {
            for (aadLen in listOf(0, 5, 16, 33)) {
                val key = Utils.randomBytes(ChaCha20Poly1305.KEY_SIZE)
                val nonce = Utils.randomBytes(ChaCha20Poly1305.NONCE_SIZE)
                val plain = if (len == 0) ByteArray(0) else Utils.randomBytes(len)
                val aad = if (aadLen == 0) ByteArray(0) else Utils.randomBytes(aadLen)

                val bc = BcChaCha20Poly1305()
                bc.init(true, AEADParameters(KeyParameter(key), 128, nonce, aad))
                val bcOut = ByteArray(bc.getOutputSize(plain.size))
                var pos = bc.processBytes(plain, 0, plain.size, bcOut, 0)
                pos += bc.doFinal(bcOut, pos)

                val actual = ChaCha20Poly1305.encrypt(key, nonce, plain, aad)
                assertArrayEquals(bcOut, actual, "mismatch for len=$len aadLen=$aadLen")
            }
        }
    }

    @Test
    fun `verify returns true for valid and false for tampered ciphertext`() {
        val key = Utils.randomBytes(ChaCha20Poly1305.KEY_SIZE)
        val nonce = ChaCha20Poly1305.nonce()
        val plain = "hello world".toByteArray()

        val cipher = ChaCha20Poly1305.encrypt(key, nonce, plain)
        assertTrue(ChaCha20Poly1305.verify(key, nonce, cipher))

        val tampered = cipher.copyOf()
        tampered[0] = (tampered[0] + 1).toByte()
        assertFalse(ChaCha20Poly1305.verify(key, nonce, tampered))
    }

    @Test
    fun `decrypt throws SecurityException on tampered tag`() {
        val key = Utils.randomBytes(ChaCha20Poly1305.KEY_SIZE)
        val nonce = ChaCha20Poly1305.nonce()
        val plain = "hello world".toByteArray()

        val cipher = ChaCha20Poly1305.encrypt(key, nonce, plain)
        cipher[cipher.size - 1] = (cipher[cipher.size - 1] + 1).toByte()

        assertThrows(SecurityException::class.java) {
            ChaCha20Poly1305.decrypt(key, nonce, cipher)
        }
    }

    @Test
    fun `decrypt throws SecurityException on tampered AAD`() {
        val key = Utils.randomBytes(ChaCha20Poly1305.KEY_SIZE)
        val nonce = ChaCha20Poly1305.nonce()
        val plain = "hello world".toByteArray()
        val aad = "original aad".toByteArray()

        val cipher = ChaCha20Poly1305.encrypt(key, nonce, plain, aad)
        val tamperedAad = "tampered aad".toByteArray()

        assertThrows(SecurityException::class.java) {
            ChaCha20Poly1305.decrypt(key, nonce, cipher, tamperedAad)
        }
    }

    @Test
    fun `decrypt throws on ciphertext shorter than the tag`() {
        val key = Utils.randomBytes(ChaCha20Poly1305.KEY_SIZE)
        val nonce = ChaCha20Poly1305.nonce()

        assertThrows(IllegalArgumentException::class.java) {
            ChaCha20Poly1305.decrypt(key, nonce, ByteArray(ChaCha20Poly1305.TAG_SIZE - 1))
        }
    }

    @Test
    fun `invalid key or nonce size throws`() {
        val key = Utils.randomBytes(ChaCha20Poly1305.KEY_SIZE)
        val nonce = Utils.randomBytes(ChaCha20Poly1305.NONCE_SIZE)
        val plain = ByteArray(16)

        assertThrows(IllegalArgumentException::class.java) { ChaCha20Poly1305.encrypt(ByteArray(31), nonce, plain) }
        assertThrows(IllegalArgumentException::class.java) { ChaCha20Poly1305.encrypt(ByteArray(33), nonce, plain) }
        assertThrows(IllegalArgumentException::class.java) { ChaCha20Poly1305.encrypt(key, ByteArray(11), plain) }
        assertThrows(IllegalArgumentException::class.java) { ChaCha20Poly1305.encrypt(key, ByteArray(13), plain) }
    }

    @Test
    fun `empty plaintext produces only the tag`() {
        val key = Utils.randomBytes(ChaCha20Poly1305.KEY_SIZE)
        val nonce = ChaCha20Poly1305.nonce()

        val result = ChaCha20Poly1305.encrypt(key, nonce, ByteArray(0))
        assertEquals(ChaCha20Poly1305.TAG_SIZE, result.size)
        assertArrayEquals(ByteArray(0), ChaCha20Poly1305.decrypt(key, nonce, result))
    }
}



