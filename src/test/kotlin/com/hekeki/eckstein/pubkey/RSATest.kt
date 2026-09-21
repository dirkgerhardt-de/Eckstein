/**
 * RSATest - Class to test encryption and decryption with RSA
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
package com.hekeki.eckstein.pubkey

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import java.security.KeyFactory
import java.security.Signature
import java.security.spec.RSAPrivateCrtKeySpec
import java.security.spec.RSAPublicKeySpec
import javax.crypto.Cipher

class RSATest {

    private val keyPair = RSA.keyPair(1024)

    private fun jcaPublicKey(publicKey: RSAPublicKey): java.security.PublicKey {
        val spec = RSAPublicKeySpec(publicKey.n, publicKey.e)
        return KeyFactory.getInstance("RSA").generatePublic(spec)
    }

    private fun jcaPrivateKey(privateKey: RSAPrivateKey): java.security.PrivateKey {
        val spec = RSAPrivateCrtKeySpec(
            privateKey.n, privateKey.e, privateKey.d,
            privateKey.p, privateKey.q,
            privateKey.exp1, privateKey.exp2, privateKey.coe
        )
        return KeyFactory.getInstance("RSA").generatePrivate(spec)
    }

    @Test
    fun `our ciphertext is decryptable by javax crypto (PKCS1 padding format compliance)`() {
        val message = "Hello RSA World! This is a test message.".toByteArray()
        val encrypted = RSA.encrypt(message, keyPair.publicKey)

        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.DECRYPT_MODE, jcaPrivateKey(keyPair.privateKey))
        val decrypted = cipher.doFinal(encrypted)

        assertArrayEquals(message, decrypted, "javax.crypto could not decrypt our PKCS1-padded ciphertext - padding format is not spec-compliant")
    }

    @Test
    fun `javax crypto ciphertext is decryptable by our implementation`() {
        val message = "Hello from the other side, RSA!".toByteArray()

        val cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding")
        cipher.init(Cipher.ENCRYPT_MODE, jcaPublicKey(keyPair.publicKey))
        val encrypted = cipher.doFinal(message)

        val decrypted = RSA.decrypt(encrypted, keyPair.privateKey)
        assertArrayEquals(message, decrypted, "our implementation could not decrypt a standard PKCS1-padded ciphertext")
    }

    @Test
    fun `many roundtrips with random padding never corrupt the message`() {
        // Uses a small key so the padding string is short and any zero-byte-in-padding bug
        // (violating PKCS1's "padding must be nonzero" requirement) surfaces quickly.
        val smallKeyPair = RSA.keyPair(512)
        val message = byteArrayOf(1, 2, 3, 4, 5)

        for (i in 0 until 300) {
            val encrypted = RSA.encrypt(message, smallKeyPair.publicKey)
            val decrypted = RSA.decrypt(encrypted, smallKeyPair.privateKey)
            assertArrayEquals(message, decrypted, "roundtrip mismatch on iteration $i - likely a zero byte in PKCS1 padding")
        }
    }

    @Test
    fun `our signature is verifiable by javax crypto Signature (EMSA-PKCS1-v1_5 format compliance)`() {
        val message = "Sign this message please".toByteArray()
        val signature = RSA.sign(message, keyPair.privateKey, RSA.SIGH.SHA256)

        val verifier = Signature.getInstance("SHA256withRSA")
        verifier.initVerify(jcaPublicKey(keyPair.publicKey))
        verifier.update(message)

        assertTrue(verifier.verify(signature), "javax.crypto could not verify our signature - EMSA-PKCS1-v1_5 format is not spec-compliant")
    }

    @Test
    fun `javax crypto signature is verifiable by our implementation`() {
        val message = "Please verify this signed message".toByteArray()

        val signer = Signature.getInstance("SHA256withRSA")
        signer.initSign(jcaPrivateKey(keyPair.privateKey))
        signer.update(message)
        val signature = signer.sign()

        assertTrue(RSA.verify(message, signature, keyPair.publicKey, RSA.SIGH.SHA256), "our implementation could not verify a standard PKCS1 signature")
    }

    @Test
    fun `sign and verify roundtrip works for all hash algorithms`() {
        val message = "Message to sign with different hashes".toByteArray()
        for (sigh in RSA.SIGH.values()) {
            val signature = RSA.sign(message, keyPair.privateKey, sigh)
            assertTrue(RSA.verify(message, signature, keyPair.publicKey, sigh), "roundtrip failed for $sigh")
        }
    }

    @Test
    fun `verify fails for tampered message`() {
        val message = "Original message".toByteArray()
        val tampered = "Tampered message".toByteArray()
        val signature = RSA.sign(message, keyPair.privateKey)

        assertTrue(!RSA.verify(tampered, signature, keyPair.publicKey))
    }

    @Test
    fun `encrypt decrypt roundtrip works with our own implementation`() {
        val message = "Roundtrip test message".toByteArray()
        val encrypted = RSA.encrypt(message, keyPair.publicKey)
        val decrypted = RSA.decrypt(encrypted, keyPair.privateKey)
        assertArrayEquals(message, decrypted)
    }
}

