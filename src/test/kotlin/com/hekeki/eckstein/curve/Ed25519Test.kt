package com.hekeki.eckstein.curve

import com.hekeki.eckstein.utils.Utils
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.RepeatedTest
import org.junit.jupiter.api.Test

class Ed25519Test {

    @RepeatedTest(15)
    fun `public key derivation matches BouncyCastle Ed25519 for random seeds`() {
        val seed = Utils.randomBytes(32)

        val bcPrivate = Ed25519PrivateKeyParameters(seed, 0)
        val bcPublicBytes = ByteArray(32)
        bcPrivate.generatePublicKey().encode(bcPublicBytes, 0)

        // reuse our keyPair() machinery by wrapping the same seed ourselves is not possible
        // since keyPair() generates its own random seed - so we call sign()/publicKey via a
        // KeyPair constructed from the same seed bytes and let sign() derive things internally.
        val ourPublicBytes = derivePublicKey(seed)

        assertArrayEquals(bcPublicBytes, ourPublicBytes, "public key length/content must always be exactly 32 bytes and match RFC 8032")
    }

    @RepeatedTest(15)
    fun `signature is byte-identical to BouncyCastle EdDSA signature`() {
        val seed = Utils.randomBytes(32)
        val message = Utils.randomBytes(64)

        val bcPrivate = Ed25519PrivateKeyParameters(seed, 0)
        val bcSigner = Ed25519Signer()
        bcSigner.init(true, bcPrivate)
        bcSigner.update(message, 0, message.size)
        val bcSignature = bcSigner.generateSignature()

        val ourSignature = signWithSeed(seed, message)

        assertArrayEquals(bcSignature, ourSignature, "EdDSA is deterministic - signatures must be byte-identical")
    }

    @RepeatedTest(15)
    fun `own sign and verify roundtrip always succeeds`() {
        val keyPair = Ed25519.keyPair()
        val message = Utils.randomBytes(64)

        val signature = Ed25519.sign(message, keyPair)

        assertTrue(Ed25519.verify(signature, message, keyPair.publicKey), "a freshly created signature must always verify successfully")
    }

    @Test
    fun `tampered message fails verification`() {
        val keyPair = Ed25519.keyPair()
        val message = "hello world".toByteArray()
        val signature = Ed25519.sign(message, keyPair)

        val tampered = "hello World".toByteArray()

        assertTrue(!Ed25519.verify(signature, tampered, keyPair.publicKey))
    }

    @Test
    fun `signature verifies with BouncyCastle and vice versa`() {
        val seed = Utils.randomBytes(32)
        val message = "cross verification test".toByteArray()

        val bcPrivate = Ed25519PrivateKeyParameters(seed, 0)
        val bcPublicBytes = ByteArray(32)
        bcPrivate.generatePublicKey().encode(bcPublicBytes, 0)

        val ourSignature = signWithSeed(seed, message)

        // BC verifies our signature
        val bcVerifier = Ed25519Signer()
        bcVerifier.init(false, Ed25519PublicKeyParameters(bcPublicBytes, 0))
        bcVerifier.update(message, 0, message.size)
        assertTrue(bcVerifier.verifySignature(ourSignature))

        // we verify BC's signature
        val bcSigner = Ed25519Signer()
        bcSigner.init(true, bcPrivate)
        bcSigner.update(message, 0, message.size)
        val bcSignature = bcSigner.generateSignature()

        assertTrue(Ed25519.verify(bcSignature, message, PublicKey(bcPublicBytes)))
    }

    private fun derivePublicKey(seed: ByteArray): ByteArray {
        return Ed25519.publicKey(seed)
    }

    private fun signWithSeed(seed: ByteArray, message: ByteArray): ByteArray {
        val publicBytes = Ed25519.publicKey(seed)
        val keyPair = KeyPair(PublicKey(publicBytes), PrivateKey(seed))
        return Ed25519.sign(message, keyPair)
    }
}

