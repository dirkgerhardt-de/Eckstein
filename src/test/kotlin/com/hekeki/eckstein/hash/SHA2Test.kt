/**
 * SHA2Test - Class to test sha2 function
 *
 * Copyright (c) 2018 - 2026 Dirk Gerhardt
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */
package com.hekeki.eckstein.hash

import com.hekeki.eckstein.encoding.Hex
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.TestInstance
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.MethodSource
import java.security.MessageDigest

class SHA2Test {

    /** Algorithm name in the JDK + the corresponding eckstein function. */
    private data class Algo(val jdkName: String, val hash: (String) -> String)

    private val algorithms = listOf(
        Algo("SHA-224") { SHA2.sha224(it) },
        Algo("SHA-256") { SHA2.sha256(it) },
        Algo("SHA-384") { SHA2.sha384(it) },
        Algo("SHA-512") { SHA2.sha512(it) }
    )

    private val commonInputs = listOf(
        "a",
        "abc",
        "abcdefghijklmnopqrstuvwxyz",
        "message digest",
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
        "A quick movement of the enemy will jeopardize six gunboats.",
        "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
    )

    /**
     * Known answer tests, grouped by algorithm.
     * TODO: SHA-384("") is not yet covered by a fixed value - insert the
     * FIPS 180-4 / Bouncy Castle result here.
     */
    private val knownAnswers: Map<String, Map<String, String>> = mapOf(
        "SHA-224" to mapOf(
            "a" to "abd37534c7d9a2efb9465de931cd7055ffdb8879563ae98078d6d6d5",
            "abc" to "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7",
            "abcdefghijklmnopqrstuvwxyz" to "45a5f72c39c5cff2522eb3429799e49e5f44b356ef926bcf390dccc2",
            "message digest" to "2cb21c83ae2f004de7e81c3c7019cbcb65b71ab656b22d6d0c39b8eb",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "bff72b4fcb7d75e5632900ac5f90d219e05e97a7bde72e740db393d9",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "b50aecbe4e9bb0b57bc5f3ae760a8e01db24f203fb3cdcd13148046e",
            "A quick movement of the enemy will jeopardize six gunboats." to "2f28d06085fc21406330807d363f6bab28397db0961f69e46adbfd90",
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an." to "c351077fb359c8dc9f87adb486826bdb92894aca9090095d2ca11133"
        ),
        "SHA-256" to mapOf(
            "a" to "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            "abc" to "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "abcdefghijklmnopqrstuvwxyz" to "71c480df93d6ae2f1efad1447c66c9525e316218cf51fc8d9ed832f2daf18b73",
            "message digest" to "f7846f55cf23e14eebeab5b4e1550cad5b509e3348fbc4efa3a1413d393cb650",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "db4bfcbd4da0cd85a60c3c37d3fbd8805c77f15fc6b1fdfe614ee0a7c8fdb4c0",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "f371bc4a311f2b009eef952dd83ca80e2b60026c8e935592d0f9c308453c813e",
            "A quick movement of the enemy will jeopardize six gunboats." to "44c6ca4bc6499411de24a6bb71945b3043e08d2bf5f62b5527c20f72b2279531",
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an." to "769d3267b99ee6a8c9adcacaec064d34dbce28a43762e1b2585c25318a67dbbd"
        ),
        "SHA-384" to mapOf(
            "a" to "54a59b9f22b0b80880d8427e548b7c23abd873486e1f035dce9cd697e85175033caa88e6d57bc35efae0b5afd3145f31",
            "abc" to "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7",
            "abcdefghijklmnopqrstuvwxyz" to "feb67349df3db6f5924815d6c3dc133f091809213731fe5c7b5f4999e463479ff2877f5f2936fa63bb43784b12f3ebb4",
            "message digest" to "473ed35167ec1f5d8e550368a3db39be54639f828868e9454c239fc8b52e3c61dbd0d8b4de1390c256dcbb5d5fd99cd5",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "1761336e3f7cbfe51deb137f026f89e01a448e3b1fafa64039c1464ee8732f11a5341a6f41e0c202294736ed64db1a84",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "b12932b0627d1c060942f5447764155655bd4da0c9afa6dd9b9ef53129af1b8fb0195996d2de9ca0df9d821ffee67026",
            "A quick movement of the enemy will jeopardize six gunboats." to "bf58ce1ace30308a48e61ba626033ff933087210a3372086a418159a53df22813a1b57501161e0301b8c61a769a62901",
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an." to "faf1258731db71195f8358b160914d235141b2c0bb7d203c2e15b9d44bee4efa8c919368a463a0dcf3486bbc16cce0c1"
        ),
        "SHA-512" to mapOf(
            "" to "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b" +
                    "931bd47417a81a538327af927da3e",
            "a" to "1f40fc92da241694750979ee6cf582f2d5d7d28e18335de05abc54d0560e0f5302860c652bf08d560252aa5e74210546f36" +
                    "9fbbbce8c12cfc7957b2652fe9a75",
            "abc" to "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454" +
                    "d4423643ce80e2a9ac94fa54ca49f",
            "abcdefghijklmnopqrstuvwxyz" to "4dbff86cc2ca1bae1e16468a05cb9881c97f1753bce3619034898faa1aabe429955a1bf8ec483d7421fe3c1646613a59ed5" +
                    "441fb0f321389f77f48a879c7b1f1",
            "message digest" to "107dbf389d9e9f71a3a95f6c055b9251bc5268c2be16d6c13492ea45b0199f3309e16455ab1e96118e8a905d5597b72038d" +
                    "db372a89826046de66687bb420e7c",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f536cfc7a9996c45c8370583e0a78fa4a90041d71a4ceab742" +
                    "3f19c71b9d5a3e01249f0bebd5894",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "72ec1ef1124a45b047e8b7c75a932195135bb61de24ec0d1914042246e0aec3a2354e093d76f3048b456764346900cb130d" +
                    "2a4fd5dd16abb5e30bcb850dee843",
            "A quick movement of the enemy will jeopardize six gunboats." to "df20f8b85d47ff4030b84ac52d10245da65a7dec47bc151cc4ffb2a35b36e44d0ea903bd6e9967fd5e193940241f8fe9ca5" +
                    "269f1d585b739830db2e93b9cd125",
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an." to "693f39c78ee05925db3f3ea91fde8f1f22435986a8bf6bce6fbafae0a453fe8c4582aa4cec5959768b3c975bb5c3127093b" +
                    "2a3c4188bab8a845cce02ae5e1366",
            "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, " +
                    "sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit " +
                    "amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam " +
                    "voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet." to
                    "9b75ddb74674b45ab738f84f73ef25c833d7d33d7c72d2556f13274d753259187386bf91dadf8e6a735e6111d703d3ffbabf64d827aaec64d5c6c33259260ce9"
        )
    )

    private fun jdkHash(algorithm: String, message: String): String =
        Hex.encode(MessageDigest.getInstance(algorithm).digest(message.toByteArray()))

    /** Additional inputs for the JDK reference comparison (multi-block, long). */
    private val additionalReferenceInputs = listOf(
        "",
        "The quick brown fox jumps over the lazy dog",
        "a".repeat(1000),
        "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
    )

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    inner class KnownAnswerTests {

        @ParameterizedTest(name = "{0}: \"{1}\"")
        @MethodSource("knownAnswerCases")
        fun `matches known answer test vectors`(algo: String, input: String, expected: String) {
            val hash = algorithms.first { it.jdkName == algo }.hash
            assertEquals(expected, hash(input), "KAT mismatch for $algo")
        }

        fun knownAnswerCases(): List<Arguments> =
            knownAnswers.flatMap { (algo, cases) ->
                cases.map { (input, expected) -> Arguments.of(algo, input, expected) }
            }
    }

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    inner class JdkReferenceTests {

        @ParameterizedTest(name = "{0} matches JDK for input #{1}")
        @MethodSource("referenceCases")
        fun `matches JDK reference implementation`(algo: String, inputIndex: Int, input: String) {
            val hash = algorithms.first { it.jdkName == algo }.hash
            assertEquals(jdkHash(algo, input), hash(input), "Mismatch for $algo at index $inputIndex")
        }

        fun referenceCases(): List<Arguments> {
            val inputs = commonInputs + additionalReferenceInputs
            return algorithms.flatMap { algo ->
                inputs.mapIndexed { i, input -> Arguments.of(algo.jdkName, i, input) }
            }
        }
    }

    @Nested
    inner class EmptyInputTests {

        @Test
        fun `sha224 of empty string matches FIPS 180-4`() {
            assertEquals("d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f", SHA2.sha224(""))
        }

        @Test
        fun `sha256 of empty string matches FIPS 180-4`() {
            assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", SHA2.sha256(""))
        }

        @Test
        fun `sha512 of empty string matches FIPS 180-4`() {
            assertEquals(
                "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b" +
                        "931bd47417a81a538327af927da3e",
                SHA2.sha512("")
            )
        }

        // TODO: sha384("") fehlt noch als fester Wert (siehe Hinweis unten).
    }

    @Nested
    inner class PaddingBoundaryTests {

        @Test
        fun `boundary lengths where message length equals the padding target modulo block size`() {
            // Regression test: for SHA-224/256 the padding target is 56 bytes mod 64,
            // for SHA-384/512 it is 112 bytes mod 128. When the message length already
            // equals that boundary, the 0x80 padding marker must still fit into a
            // freshly appended block instead of overwriting the length field.
            for (len in listOf(0, 1, 55, 56, 57, 63, 64, 111, 112, 113, 127, 128, 200)) {
                val msg = "x".repeat(len)
                for (algo in algorithms) {
                    assertEquals(jdkHash(algo.jdkName, msg), algo.hash(msg), "${algo.jdkName} mismatch for length $len")
                }
            }
        }
    }
}