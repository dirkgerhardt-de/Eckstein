/**
 * Curve25519Test - Class to test ECDH over Curve25519
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
package com.hekeki.eckstein.curve

import com.hekeki.eckstein.encoding.Hex
import com.hekeki.eckstein.utils.Utils
import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.RepeatedTest
import org.junit.jupiter.api.Test
import java.security.SecureRandom

class Curve25519Test {

    companion object {
        /** RFC 7748 §4.1 test vector: Alice private / Bob private / expected shared secret (hex). */
        private val RFC7748_VECTOR = Triple(
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
        )

        private val BASE_POINT = PublicKey(byteArrayOf(9) + ByteArray(31))

        private const val KEY_SIZE = 32
    }

    @Test
    fun `key pair has correct component sizes`() {
        val aliceKeyPair = Curve25519.keyPair()
        val bobKeyPair = Curve25519.keyPair()

        assertEquals(KEY_SIZE, aliceKeyPair.privateKey.bytes.size)
        assertEquals(KEY_SIZE, aliceKeyPair.publicKey.bytes.size)
        assertEquals(KEY_SIZE, bobKeyPair.privateKey.bytes.size)
        assertEquals(KEY_SIZE, bobKeyPair.publicKey.bytes.size)
    }

    @Test
    fun `different key pairs produce different keys`() {
        val a = Curve25519.keyPair()
        val b = Curve25519.keyPair()

        assertFalse(a.privateKey.bytes.contentEquals(b.privateKey.bytes), "private keys must differ")
        assertFalse(a.publicKey.bytes.contentEquals(b.publicKey.bytes), "public keys must differ")
    }

    @Test
    fun `edge case private keys do not throw`() {
        val zero = PrivateKey(ByteArray(KEY_SIZE))
        val max = PrivateKey(ByteArray(KEY_SIZE) { 0xFF.toByte() })

        assertEquals(KEY_SIZE, Curve25519.sharedKey(zero, BASE_POINT).size)
        assertEquals(KEY_SIZE, Curve25519.sharedKey(max, BASE_POINT).size)
    }

    @Test
    fun `shared key matches RFC 7748 test vector`() {
        val alicePrivKey = Hex.toByteArray(RFC7748_VECTOR.first)
        val alicePubKey = Hex.toByteArray("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        val aliceKeyPair = KeyPair(PublicKey(alicePubKey), PrivateKey(alicePrivKey))

        val bobPrivKey = Hex.toByteArray(RFC7748_VECTOR.second)
        val bobPubKey = Hex.toByteArray("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        val bobKeyPair = KeyPair(PublicKey(bobPubKey), PrivateKey(bobPrivKey))

        val aliceSharedKey = Curve25519.sharedKey(aliceKeyPair.privateKey, bobKeyPair.publicKey)
        val bobSharedKey = Curve25519.sharedKey(bobKeyPair.privateKey, aliceKeyPair.publicKey)

        assertEquals(RFC7748_VECTOR.third, Hex.encode(aliceSharedKey), "Alice's shared key mismatch")
        assertEquals(RFC7748_VECTOR.third, Hex.encode(bobSharedKey), "Bob's shared key mismatch")
        assertArrayEquals(aliceSharedKey, bobSharedKey, "symmetry must hold")
    }

    @RepeatedTest(20)
    fun `own key exchange is symmetric`() {
        val alice = Curve25519.keyPair()
        val bob = Curve25519.keyPair()

        val sharedAlice = Curve25519.sharedKey(alice.privateKey, bob.publicKey)
        val sharedBob = Curve25519.sharedKey(bob.privateKey, alice.publicKey)

        assertArrayEquals(sharedAlice, sharedBob, "ECDH symmetry must hold for random keys")
    }

    @RepeatedTest(20)
    fun `public key derivation matches BouncyCastle X25519`() {
        val privateBytes = Utils.randomBytes(KEY_SIZE)

        // sharedKey(sk, basePoint) computes scalarMultiplication(clamp(sk), BASE_POINT)
        val ourPublicKeyBytes = Curve25519.sharedKey(PrivateKey(privateBytes), BASE_POINT)

        val bcPrivate = X25519PrivateKeyParameters(privateBytes, 0)
        val bcPublicBytes = ByteArray(KEY_SIZE)
        bcPrivate.generatePublicKey().encode(bcPublicBytes, 0)

        assertArrayEquals(bcPublicBytes, ourPublicKeyBytes, "public key derivation must match BC")
    }

    @RepeatedTest(20)
    fun `shared secret matches BouncyCastle X25519Agreement in both directions`() {
        val ourKeyPair = Curve25519.keyPair()

        val bcPrivate = X25519PrivateKeyParameters(SecureRandom())
        val bcPublicBytes = ByteArray(KEY_SIZE)
        bcPrivate.generatePublicKey().encode(bcPublicBytes, 0)

        // we compute the shared secret using BC's public key
        val ourShared = Curve25519.sharedKey(ourKeyPair.privateKey, PublicKey(bcPublicBytes))

        // BC computes the shared secret using our public key
        val agreement = X25519Agreement()
        agreement.init(bcPrivate)
        val bcShared = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(ourKeyPair.publicKey.bytes, 0), bcShared, 0)

        assertArrayEquals(bcShared, ourShared, "shared secret must match BC in both directions")
    }
}