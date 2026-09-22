/**
 * Ed25519Test -  Class to test EdDSA over Curve25519
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
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.RepeatedTest
import org.junit.jupiter.api.Test

class Ed25519Test {

    companion object {

        /** RFC 8032 §7.1 test vectors: privateKey / publicKey / message / signature (all hex). */
        private val RFC8032_VECTORS = listOf(
            Vector(
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
            ),
            Vector(
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
            ),
            Vector(
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"
            ),
            Vector(
                "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
                "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
                // Test vector "TEST 1024" from RFC 8032 §7.1
                "08b8b2b733424243760fe426a4b54908632110a66c2f6591eabd3345e3e4eb98fa6e264bf09efe12ee50f8f54e9f77b1e355f6c50544e23fb1433ddf73be84d8" +
                        "79de7c0046dc4996d9e773f4bc9efe5738829adb26c81b37c93a1b270b20329d658675fc6ea534e0810a4432826bf58c941efb65d57a338bbd2e26640f89ffbc" +
                        "1a858efcb8550ee3a5e1998bd177e93a7363c344fe6b199ee5d02e82d522c4feba15452f80288a821a579116ec6dad2b3b310da903401aa62100ab5d1a36553e" +
                        "06203b33890cc9b832f79ef80560ccb9a39ce767967ed628c6ad573cb116dbefefd75499da96bd68a8a97b928a8bbc103b6621fcde2beca1231d206be6cd9ec7" +
                        "aff6f6c94fcd7204ed3455c68c83f4a41da4af2b74ef5c53f1d8ac70bdcb7ed185ce81bd84359d44254d95629e9855a94a7c1958d1f8ada5d0532ed8a5aa3fb2" +
                        "d17ba70eb6248e594e1a2297acbbb39d502f1a8c6eb6f1ce22b3de1a1f40cc24554119a831a9aad6079cad88425de6bde1a9187ebb6092cf67bf2b13fd65f270" +
                        "88d78b7e883c8759d2c4f5c65adb7553878ad575f9fad878e80a0c9ba63bcbcc2732e69485bbc9c90bfbd62481d9089beccf80cfe2df16a2cf65bd92dd597b07" +
                        "07e0917af48bbb75fed413d238f5555a7a569d80c3414a8d0859dc65a46128bab27af87a71314f318c782b23ebfe808b82b0ce26401d2e22f04d83d1255dc51a" +
                        "ddd3b75a2b1ae0784504df543af8969be3ea7082ff7fc9888c144da2af58429ec96031dbcad3dad9af0dcbaaaf268cb8fcffead94f3c7ca495e056a9b47acdb7" +
                        "51fb73e666c6c655ade8297297d07ad1ba5e43f1bca32301651339e22904cc8c42f58c30c04aafdb038dda0847dd988dcda6f3bfd15c4b4c4525004aa06eeff8" +
                        "ca61783aacec57fb3d1f92b0fe2fd1a85f6724517b65e614ad6808d6f6ee34dff7310fdc82aebfd904b01e1dc54b2927094b2db68d6f903b68401adebf5a7e08" +
                        "d78ff4ef5d63653a65040cf9bfd4aca7984a74d37145986780fc0b16ac451649de6188a7dbdf191f64b5fc5e2ab47b57f7f7276cd419c17a3ca8e1b939ae49e4" +
                        "88acba6b965610b5480109c8b17b80e1b7b750dfc7598d5d5011fd2dcc5600a32ef5b52a1ecc820e308aa342721aac0943bf6686b64b2579376504ccc493d97e" +
                        "6aed3fb0f9cd71a43dd497f01f17c0e2cb3797aa2a2f256656168e6c496afc5fb93246f6b1116398a346f1a641f3b041e989f7914f90cc2c7fff357876e506b5" +
                        "0d334ba77c225bc307ba537152f3f1610e4eafe595f6d9d90d11faa933a15ef1369546868a7f3a45a96768d40fd9d03412c091c6315cf4fde7cb68606937380d" +
                        "b2eaaa707b4c4185c32eddcdd306705e4dc1ffc872eeee475a64dfac86aba41c0618983f8741c5ef68d3a101e8a3b8cac60c905c15fc910840b94c00a0b9d0",
                "0aab4c900501b3e24d7cdf4663326a3a87df5e4843b2cbdb67cbf6e460fec350aa5371b1508f9f4528ecea23c436d94b5e8fcd4f681e30a6ac00a9704a188a03"
            )
        )

        private data class Vector(val privateKey: String, val publicKey: String, val message: String, val signature: String)

        /** (label, signatureLength, publicKeyLength) for invalid input verification. */
        private val INVALID_VERIFY_INPUTS = listOf(
            Triple("signature too short", 63, 32),
            Triple("signature too long", 65, 32),
            Triple("public key too short", 64, 31),
            Triple("public key too long", 64, 33)
        )

        /** Size of an Ed25519 signature / public key in bytes. */
        private const val SIGNATURE_SIZE = 64
        private const val PUBLIC_KEY_SIZE = 32
    }

    @Test
    fun `key pair has correct component sizes`() {
        val keyPair = Ed25519.keyPair()
        assertEquals(32, keyPair.privateKey.bytes.size)
        assertEquals(32, keyPair.publicKey.bytes.size)
    }

    @Test
    fun `sign produces RFC 8032 test vector signatures`() {
        RFC8032_VECTORS.forEachIndexed { i, vector ->
            val keyPair = keyPairFrom(vector.privateKey, vector.publicKey)
            val signature = Ed25519.sign(Hex.toByteArray(vector.message), keyPair)

            assertEquals(vector.signature, Hex.encode(signature), "sign mismatch in RFC 8032 vector #$i")
        }
    }

    @Test
    fun verify() {
        val keyPair = Ed25519.keyPair()
        val message = Utils.randomBytes(1024)

        val signature = Ed25519.sign(message, keyPair)
        assertTrue(Ed25519.verify(signature, message, keyPair.publicKey))
    }

    @RepeatedTest(15)
    fun `own sign and verify roundtrip always succeeds`() {
        val keyPair = Ed25519.keyPair()
        val message = Utils.randomBytes(64)

        val signature = Ed25519.sign(message, keyPair)

        assertTrue(Ed25519.verify(signature, message, keyPair.publicKey),
            "a freshly created signature must always verify successfully")
    }

    @Test
    fun `tampered message fails verification`() {
        val keyPair = Ed25519.keyPair()
        val message = "hello world".toByteArray()
        val signature = Ed25519.sign(message, keyPair)

        assertFalse(Ed25519.verify(signature, "hello World".toByteArray(), keyPair.publicKey),
            "verification must fail for a modified message")
    }

    @RepeatedTest(15)
    fun `public key derivation matches BouncyCastle Ed25519 for random seeds`() {
        val seed = Utils.randomBytes(PUBLIC_KEY_SIZE)

        val bcPrivate = Ed25519PrivateKeyParameters(seed, 0)
        val bcPublicBytes = ByteArray(PUBLIC_KEY_SIZE)
        bcPrivate.generatePublicKey().encode(bcPublicBytes, 0)

        assertArrayEquals(bcPublicBytes, Ed25519.publicKey(seed),
            "public key derivation must match RFC 8032 / BouncyCastle")
    }

    @RepeatedTest(15)
    fun `signature is byte-identical to BouncyCastle EdDSA signature`() {
        val seed = Utils.randomBytes(PUBLIC_KEY_SIZE)
        val message = Utils.randomBytes(64)

        val bcSignature = bcSign(seed, message)
        val ourSignature = signWithSeed(seed, message)

        assertArrayEquals(bcSignature, ourSignature, "EdDSA is deterministic - signatures must be byte-identical")
    }

    @Test
    fun `signature verifies with BouncyCastle and vice versa`() {
        val seed = Utils.randomBytes(PUBLIC_KEY_SIZE)
        val message = "cross verification test".toByteArray()

        val bcPrivate = Ed25519PrivateKeyParameters(seed, 0)
        val bcPublicBytes = ByteArray(PUBLIC_KEY_SIZE)
        bcPrivate.generatePublicKey().encode(bcPublicBytes, 0)

        val ourSignature = signWithSeed(seed, message)

        // BC verifies our signature
        val bcVerifier = Ed25519Signer()
        bcVerifier.init(false, Ed25519PublicKeyParameters(bcPublicBytes, 0))
        bcVerifier.update(message, 0, message.size)
        assertTrue(bcVerifier.verifySignature(ourSignature), "BC must accept our signature")

        // we verify BC's signature
        val bcSignature = bcSign(seed, message)
        assertTrue(Ed25519.verify(bcSignature, message, PublicKey(bcPublicBytes)), "we must accept BC's signature")
    }

    @Test
    fun `verify throws on invalid input lengths`() {
        INVALID_VERIFY_INPUTS.forEach { (label, signatureLength, publicKeyLength) ->
            assertThrows(IllegalArgumentException::class.java, {
                Ed25519.verify(Utils.randomBytes(signatureLength), ByteArray(0), PublicKey(ByteArray(publicKeyLength)))
            }, "expected IllegalArgumentException for $label")
        }
    }

    private fun keyPairFrom(privateKeyHex: String, publicKeyHex: String): KeyPair =
        KeyPair(PublicKey(Hex.toByteArray(publicKeyHex)), PrivateKey(Hex.toByteArray(privateKeyHex)))

    private fun signWithSeed(seed: ByteArray, message: ByteArray): ByteArray {
        val keyPair = keyPairFrom(Hex.encode(seed), Hex.encode(Ed25519.publicKey(seed)))
        return Ed25519.sign(message, keyPair)
    }

    private fun bcSign(seed: ByteArray, message: ByteArray): ByteArray {
        val signer = Ed25519Signer()
        signer.init(true, Ed25519PrivateKeyParameters(seed, 0))
        signer.update(message, 0, message.size)
        return signer.generateSignature()
    }
}