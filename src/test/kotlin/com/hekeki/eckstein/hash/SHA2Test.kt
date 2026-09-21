package com.hekeki.eckstein.hash

import com.hekeki.eckstein.encoding.Hex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.security.MessageDigest

class SHA2Test {

    private fun jdkHash(algorithm: String, message: String): String {
        val digest = MessageDigest.getInstance(algorithm).digest(message.toByteArray())
        return Hex.encode(digest)
    }

    private val testVectors = listOf(
        "",
        "a",
        "abc",
        "message digest",
        "abcdefghijklmnopqrstuvwxyz",
        "The quick brown fox jumps over the lazy dog",
        "a".repeat(1000),
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" // classic 112-byte multi-block test string
    )

    @Test
    fun `sha224 matches JDK reference for various inputs`() {
        for (msg in testVectors) {
            assertEquals(jdkHash("SHA-224", msg), SHA2.sha224(msg), "Mismatch for input: \"$msg\"")
        }
    }

    @Test
    fun `sha256 matches JDK reference for various inputs`() {
        for (msg in testVectors) {
            assertEquals(jdkHash("SHA-256", msg), SHA2.sha256(msg), "Mismatch for input: \"$msg\"")
        }
    }

    @Test
    fun `sha384 matches JDK reference for various inputs`() {
        for (msg in testVectors) {
            assertEquals(jdkHash("SHA-384", msg), SHA2.sha384(msg), "Mismatch for input: \"$msg\"")
        }
    }

    @Test
    fun `sha512 matches JDK reference for various inputs`() {
        for (msg in testVectors) {
            assertEquals(jdkHash("SHA-512", msg), SHA2.sha512(msg), "Mismatch for input: \"$msg\"")
        }
    }

    @Test
    fun `known test vectors for empty and abc`() {
        // NIST/FIPS 180-4 known answer tests
        assertEquals("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", SHA2.sha224(""))
        assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", SHA2.sha256(""))
    }

    @Test
    fun `boundary lengths where message length equals the padding target modulo block size`() {
        // Regression test: for SHA-224/256 the padding target is 56 bytes mod 64,
        // for SHA-384/512 it is 112 bytes mod 128. When the message length already
        // equals that boundary, the 0x80 padding marker must still fit into a
        // freshly appended block instead of overwriting the length field.
        for (len in listOf(0, 1, 55, 56, 57, 63, 64, 111, 112, 113, 127, 128, 200)) {
            val msg = "x".repeat(len)
            assertEquals(jdkHash("SHA-224", msg), SHA2.sha224(msg), "SHA-224 mismatch for length $len")
            assertEquals(jdkHash("SHA-256", msg), SHA2.sha256(msg), "SHA-256 mismatch for length $len")
            assertEquals(jdkHash("SHA-384", msg), SHA2.sha384(msg), "SHA-384 mismatch for length $len")
            assertEquals(jdkHash("SHA-512", msg), SHA2.sha512(msg), "SHA-512 mismatch for length $len")
        }
    }
}


