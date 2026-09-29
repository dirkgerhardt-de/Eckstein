package com.hekeki.eckstein.pbkdf

import com.hekeki.eckstein.encoding.Hex
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
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

    @Test
    fun `convenience hash matches Bouncy Castle reference with default RFC 9106 parameters`() {
        val password = "password".toByteArray()
        val salt = "somesalt12345678".toByteArray()

        val expectedId = bcArgon2(password, salt, 3, 64 * 1024, 4, 32, ARGON2.Type.ARGON2ID)
        assertArrayEquals(expectedId, ARGON2.hashArgon2id("password", salt))

        val expectedD = bcArgon2(password, salt, 3, 64 * 1024, 4, 32, ARGON2.Type.ARGON2D)
        assertArrayEquals(expectedD, ARGON2.hashArgon2d("password", salt))

        val expectedI = bcArgon2(password, salt, 3, 64 * 1024, 4, 32, ARGON2.Type.ARGON2I)
        assertArrayEquals(expectedI, ARGON2.hashArgon2i("password", salt))
    }

    @Test
    fun `convenience hash honors custom tagLength`() {
        assertEquals(16, ARGON2.hashArgon2id("password", ARGON2.salt(16), tagLength = 16).size)
        assertEquals(48, ARGON2.hashArgon2d("password", ARGON2.salt(16), tagLength = 48).size)
        assertEquals(64, ARGON2.hashArgon2i("password", ARGON2.salt(16), tagLength = 64).size)
    }

    @Test
    fun `convenience verify accepts correct and rejects incorrect password for each variant`() {
        val salt = ARGON2.salt(16)

        val idHash = ARGON2.hashArgon2id("s3cr3t", salt)
        assertTrue(ARGON2.verifyArgon2id("s3cr3t", idHash, salt))
        assertFalse(ARGON2.verifyArgon2id("wrong", idHash, salt))

        val dHash = ARGON2.hashArgon2d("s3cr3t", salt)
        assertTrue(ARGON2.verifyArgon2d("s3cr3t", dHash, salt))
        assertFalse(ARGON2.verifyArgon2d("wrong", dHash, salt))

        val iHash = ARGON2.hashArgon2i("s3cr3t", salt)
        assertTrue(ARGON2.verifyArgon2i("s3cr3t", iHash, salt))
        assertFalse(ARGON2.verifyArgon2i("wrong", iHash, salt))
    }

    @Test
    fun `verify works with byte array password`() {
        val salt = ARGON2.salt(16)
        val pw = "s3cr3t".toByteArray()
        val tag = ARGON2.hash(pw, salt, 2, 64, 1, 32)
        assertTrue(ARGON2.verify(pw, tag, salt, 2, 64, 1))
        assertFalse(ARGON2.verify("x".toByteArray(), tag, salt, 2, 64, 1))
        assertFalse(ARGON2.verify(pw, ByteArray(2), salt, 2, 64, 1))
    }

    @Test
    fun `PHC encode and verifyEncoded roundtrip`() {
        for (type in ARGON2.Type.entries) {
            val encoded = ARGON2.encode("s3cr3t", iterations = 2, memoryKiB = 64, parallelism = 2, type = type)
            assertTrue(encoded.startsWith("\$${type.id}\$v=19\$m=64,t=2,p=2\$"))
            assertTrue(ARGON2.verifyEncoded("s3cr3t", encoded))
            assertFalse(ARGON2.verifyEncoded("wrong", encoded))
        }
    }

    @Test
    fun `verifyEncoded rejects malformed input`() {
        assertFalse(ARGON2.verifyEncoded("pw", ""))
        assertFalse(ARGON2.verifyEncoded("pw", "\$argon2x\$v=19\$m=64,t=2,p=1\$AAAAAAAAAAA\$AAAAAAAA"))
        assertFalse(ARGON2.verifyEncoded("pw", "\$argon2id\$v=19\$m=abc,t=2,p=1\$AAAAAAAAAAA\$AAAAAAAA"))
        assertFalse(ARGON2.verifyEncoded("pw", "\$argon2id\$v=19\$m=64,t=2,p=1\$!!!\$???"))
    }

    @Test
    fun `invalid parameters are rejected`() {
        val pw = "pw".toByteArray()
        val salt = ByteArray(16)
        assertThrows(IllegalArgumentException::class.java) { ARGON2.hash(pw, ByteArray(4), 1, 32, 1, 32) }
        assertThrows(IllegalArgumentException::class.java) { ARGON2.hash(pw, salt, 0, 32, 1, 32) }
        assertThrows(IllegalArgumentException::class.java) { ARGON2.hash(pw, salt, 1, 32, 1, 3) }
        assertThrows(IllegalArgumentException::class.java) { ARGON2.hash(pw, salt, 1, 7, 1, 32) }
        assertThrows(IllegalArgumentException::class.java) { ARGON2.hash(pw, salt, 1, 32, 0, 32) }
    }

    @Test
    fun `edge cases match Bouncy Castle`() {
        val salt = "somesalt12345678".toByteArray()
        for (type in ARGON2.Type.entries) {
            for (len in listOf(4, 65, 130)) {
                assertArrayEquals(
                    bcArgon2(ByteArray(0), salt, 1, 16, 1, len, type),
                    ARGON2.hash(ByteArray(0), salt, 1, 16, 1, len, type),
                    "type=$type len=$len"
                )
            }
        }
    }
}

