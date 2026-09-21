package com.hekeki.eckstein.hash

import com.hekeki.eckstein.encoding.Hex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.security.MessageDigest

class SHA3Test {

    private fun jdkHash(algorithm: String, message: String): String {
        val digest = MessageDigest.getInstance(algorithm).digest(message.toByteArray())
        return Hex.encode(digest)
    }

    @Test
    fun `sha3-256 of empty string matches known answer`() {
        // NIST/FIPS 202 known answer test for SHA3-256("")
        assertEquals("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", SHA3.sha256(""))
    }

    @Test
    fun `sha3-224 matches JDK reference for boundary lengths around block size`() {
        checkBoundaries("SHA3-224") { SHA3.sha224(it) }
    }

    @Test
    fun `sha3-256 matches JDK reference for boundary lengths around block size`() {
        checkBoundaries("SHA3-256") { SHA3.sha256(it) }
    }

    @Test
    fun `sha3-384 matches JDK reference for boundary lengths around block size`() {
        checkBoundaries("SHA3-384") { SHA3.sha384(it) }
    }

    @Test
    fun `sha3-512 matches JDK reference for boundary lengths around block size`() {
        checkBoundaries("SHA3-512") { SHA3.sha512(it) }
    }

    private fun checkBoundaries(jdkAlgo: String, hash: (String) -> String) {
        val blockSize = when (jdkAlgo) {
            "SHA3-224" -> 144
            "SHA3-256" -> 136
            "SHA3-384" -> 104
            "SHA3-512" -> 72
            else -> error("unknown")
        }
        val lengths = listOf(0, 1, blockSize - 2, blockSize - 1, blockSize, blockSize + 1, 2 * blockSize - 1, 2 * blockSize, 2 * blockSize + 1)
        for (len in lengths) {
            val msg = "x".repeat(len)
            assertEquals(jdkHash(jdkAlgo, msg), hash(msg), "Mismatch for $jdkAlgo at length $len")
        }
    }
}

