package com.hekeki.eckstein.pwkdf

import com.hekeki.eckstein.encoding.Hex
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class ARGON2Test {

    private fun bcType(type: ARGON2.Type): Int = when (type) {
        ARGON2.Type.ARGON2D -> Argon2Parameters.ARGON2_d
        ARGON2.Type.ARGON2I -> Argon2Parameters.ARGON2_i
        ARGON2.Type.ARGON2ID -> Argon2Parameters.ARGON2_id
    }

    private fun bcArgon2(
        password: ByteArray,
        salt: ByteArray,
        iterations: Int,
        memoryKiB: Int,
        parallelism: Int,
        tagLength: Int,
        type: ARGON2.Type,
        secret: ByteArray = ByteArray(0),
        associatedData: ByteArray = ByteArray(0)
    ): ByteArray {
        val builder = Argon2Parameters.Builder(bcType(type))
            .withVersion(Argon2Parameters.ARGON2_VERSION_13)
            .withIterations(iterations)
            .withMemoryAsKB(memoryKiB)
            .withParallelism(parallelism)
            .withSalt(salt)
        if (secret.isNotEmpty()) builder.withSecret(secret)
        if (associatedData.isNotEmpty()) builder.withAdditional(associatedData)
        val generator = Argon2BytesGenerator()
        generator.init(builder.build())
        val out = ByteArray(tagLength)
        generator.generateBytes(password, out)
        return out
    }

    @Test
    fun `matches Bouncy Castle reference for all variants and parameters`() {
        val password = "password".toByteArray()
        val salt = "somesalt12345678".toByteArray()
        val cases = listOf(
            // iterations, memoryKiB, parallelism, tagLength
            listOf(1, 32, 1, 32),
            listOf(2, 64, 1, 32),
            listOf(3, 128, 2, 64),
            listOf(2, 256, 4, 48),
            listOf(1, 64, 1, 16)
        )
        for (type in ARGON2.Type.entries) {
            for ((t, m, p, len) in cases) {
                val expected = bcArgon2(password, salt, t, m, p, len, type)
                val actual = ARGON2.hash(password, salt, t, m, p, len, type)
                assertArrayEquals(
                    expected, actual,
                    "Mismatch for type=$type t=$t m=$m p=$p len=$len\n" +
                        "expected=${Hex.encode(expected)}\nactual  =${Hex.encode(actual)}"
                )
            }
        }
    }

    @Test
    fun `matches Bouncy Castle reference with secret and associated data`() {
        val password = "correct horse battery staple".toByteArray()
        val salt = "0123456789abcdef".toByteArray()
        val secret = "pepper".toByteArray()
        val ad = "associated-data".toByteArray()

        for (type in ARGON2.Type.entries) {
            val expected = bcArgon2(password, salt, 3, 128, 2, 32, type, secret, ad)
            val actual = ARGON2.hash(password, salt, 3, 128, 2, 32, type, secret, ad)
            assertArrayEquals(expected, actual, "Mismatch for type=$type with secret/AD")
        }
    }

    @Test
    fun `matches official RFC 9106 test vectors`() {
        // RFC 9106 section 5: password = 32 * 0x01, salt = 16 * 0x02,
        // secret = 8 * 0x03, ad = 12 * 0x04, t=3, m=32, p=4, tagLength=32.
        val password = ByteArray(32) { 0x01 }
        val salt = ByteArray(16) { 0x02 }
        val secret = ByteArray(8) { 0x03 }
        val ad = ByteArray(12) { 0x04 }

        assertEquals(
            "512b391b6f1162975371d30919734294f868e3be3984f3c1a13a4db9fabe4acb",
            Hex.encode(ARGON2.hash(password, salt, 3, 32, 4, 32, ARGON2.Type.ARGON2D, secret, ad))
        )
        assertEquals(
            "c814d9d1dc7f37aa13f0d77f2494bda1c8de6b016dd388d29952a4c4672b6ce8",
            Hex.encode(ARGON2.hash(password, salt, 3, 32, 4, 32, ARGON2.Type.ARGON2I, secret, ad))
        )
        assertEquals(
            "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659",
            Hex.encode(ARGON2.hash(password, salt, 3, 32, 4, 32, ARGON2.Type.ARGON2ID, secret, ad))
        )
    }

    @Test
    fun `verify accepts correct and rejects incorrect password`() {
        val salt = ARGON2.salt(16)
        val hash = ARGON2.hash("s3cr3t", salt, 2, 64, 1, 32)

        assertTrue(ARGON2.verify("s3cr3t", hash, salt, 2, 64, 1))
        assertFalse(ARGON2.verify("wrong", hash, salt, 2, 64, 1))
    }

    @Test
    fun `salt returns requested size`() {
        assertEquals(16, ARGON2.salt(16).size)
        assertEquals(32, ARGON2.salt(32).size)
    }
}

