package com.hekeki.eckstein.hash

import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test

class BLAKE2bTest {

    @Test
    fun `blake2b-512 matches official RFC 7693 vectors`() {
        // Empty input
        assertEquals(
            "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419" +
                "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
            BLAKE2b.hash("")
        )
        // "abc" – the reference vector from RFC 7693 Appendix A
        assertEquals(
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
            BLAKE2b.hash("abc")
        )
    }

    @Test
    fun `blake2b matches JDK reference for various inputs`() {
        val messages = listOf(
            "",
            "a",
            "abc",
            "message digest",
            "abcdefghijklmnopqrstuvwxyz",
            "The quick brown fox jumps over the lazy dog",
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an.",
            "a".repeat(200)
        )
        for (msg in messages) {
            val expected = jdkBlake2b512(msg.toByteArray())
            assertEquals(expected, BLAKE2b.hash(msg), "Mismatch for input: \"$msg\"")
        }
    }

    @Test
    fun `blake2b supports custom digest lengths`() {
        // BLAKE2b-256 of "abc"
        assertEquals(
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
            BLAKE2b.hash("abc", 32)
        )
    }

    private fun jdkBlake2b512(message: ByteArray): String {
        val digest = org.bouncycastle.crypto.digests.Blake2bDigest(512)
        digest.update(message, 0, message.size)
        val out = ByteArray(digest.digestSize)
        digest.doFinal(out, 0)
        return com.hekeki.eckstein.encoding.Hex.encode(out)
    }
}

