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

    private val basePoint = PublicKey(byteArrayOf(9) + ByteArray(31))

    @RepeatedTest(20)
    fun `own key exchange is symmetric`() {
        val alice = Curve25519.keyPair()
        val bob = Curve25519.keyPair()

        val sharedAlice = Curve25519.sharedKey(alice.privateKey, bob.publicKey)
        val sharedBob = Curve25519.sharedKey(bob.privateKey, alice.publicKey)

        assertArrayEquals(sharedAlice, sharedBob)
    }

    @RepeatedTest(20)
    fun `public key derivation matches BouncyCastle X25519`() {
        val privateBytes = Utils.randomBytes(32)

        // publicKey(sk) is scalarMultiplication(clamp(sk), BASE_POINT), which is exactly
        // what sharedKey(sk, basePoint) computes internally - no need to expose the
        // private publicKey() function to verify it independently.
        val ourPublicKeyBytes = Curve25519.sharedKey(PrivateKey(privateBytes), basePoint)

        val bcPrivate = X25519PrivateKeyParameters(privateBytes, 0)
        val bcPublicBytes = ByteArray(32)
        bcPrivate.generatePublicKey().encode(bcPublicBytes, 0)

        assertArrayEquals(bcPublicBytes, ourPublicKeyBytes)
    }

    @RepeatedTest(20)
    fun `shared secret matches BouncyCastle X25519Agreement in both directions`() {

        val ourKeyPair = Curve25519.keyPair()

        val bcPrivate = X25519PrivateKeyParameters(SecureRandom())
        val bcPublicBytes = ByteArray(32)
        bcPrivate.generatePublicKey().encode(bcPublicBytes, 0)

        // we compute the shared secret using BC's public key
        val ourShared = Curve25519.sharedKey(ourKeyPair.privateKey, PublicKey(bcPublicBytes))

        // BC computes the shared secret using our public key
        val agreement = X25519Agreement()
        agreement.init(bcPrivate)
        val bcShared = ByteArray(agreement.agreementSize)
        agreement.calculateAgreement(X25519PublicKeyParameters(ourKeyPair.publicKey.bytes, 0), bcShared, 0)

        assertArrayEquals(bcShared, ourShared)
    }

    @Test
    fun `key pair has expected sizes`() {
        val keyPair = Curve25519.keyPair()
        assertEquals(32, keyPair.privateKey.bytes.size)
        assertEquals(32, keyPair.publicKey.bytes.size)
    }

    @Test
    fun `different key pairs produce different keys`() {
        val a = Curve25519.keyPair()
        val b = Curve25519.keyPair()

        assertFalse(a.privateKey.bytes.contentEquals(b.privateKey.bytes))
        assertFalse(a.publicKey.bytes.contentEquals(b.publicKey.bytes))
    }

    @Test
    fun `edge case private keys do not throw`() {
        val zero = PrivateKey(ByteArray(32))
        val max = PrivateKey(ByteArray(32) { 0xFF.toByte() })

        assertEquals(32, Curve25519.sharedKey(zero, basePoint).size)
        assertEquals(32, Curve25519.sharedKey(max, basePoint).size)
    }
}

