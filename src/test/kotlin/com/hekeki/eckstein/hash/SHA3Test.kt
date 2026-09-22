/**
 * SHA3Test - Class to test sha3 function
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

class SHA3Test {

    /** Algorithm name in the JDK + the corresponding eckstein function + block size in bytes. */
    private data class Algo(
        val jdkName: String,
        val hash: (String) -> String,
        val blockSize: Int
    )

    private val algorithms = listOf(
        Algo("SHA3-224", { SHA3.sha224(it) }, 144),
        Algo("SHA3-256", { SHA3.sha256(it) }, 136),
        Algo("SHA3-384", { SHA3.sha384(it) }, 104),
        Algo("SHA3-512", { SHA3.sha512(it) }, 72)
    )

    private fun jdkHash(algorithm: String, message: String): String =
        Hex.encode(MessageDigest.getInstance(algorithm).digest(message.toByteArray()))

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
     * Known answer tests from NIST/FIPS 202.
     * TODO: Add SHA3-224(""), SHA3-384(""), SHA3-512("") once verified.
     */
    private val knownAnswers: Map<String, Map<String, String>> = mapOf(
        "SHA3-224" to mapOf(
            "a" to "9e86ff69557ca95f405f081269685b38e3a819b309ee942f482b6a8b",
            "abc" to "e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
            "abcdefghijklmnopqrstuvwxyz" to "5cdeca81e123f87cad96b9cba999f16f6d41549608d4e0f4681b8239",
            "message digest" to "18768bb4c48eb7fc88e5ddb17efcf2964abd7798a39d86a4b4a1e4c8",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "a67c289b8250a6f437a20137985d605589a8c163d45261b15419556e",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "0526898e185869f91b3e2a76dd72a15dc6940a67c8164a044cd25cc8",
            "A quick movement of the enemy will jeopardize six gunboats." to "7ae913e5d3389cf429ed29db8cd4217c4b0cecd5ab0608bf2bef9355",
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an." to "42717a2fdd008e81f7d3e5c88b29487f359f821b134df804c808ae2e"
        ),
        "SHA3-256" to mapOf(
            "" to "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
            "a" to "80084bf2fba02475726feb2cab2d8215eab14bc6bdd8bfb2c8151257032ecd8b",
            "abc" to "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
            "abcdefghijklmnopqrstuvwxyz" to "7cab2dc765e21b241dbc1c255ce620b29f527c6d5e7f5f843e56288f0d707521",
            "message digest" to "edcdb2069366e75243860c18c3a11465eca34bce6143d30c8665cefcfd32bffd",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "a79d6a9da47f04a3b9a9323ec9991f2105d4c78a7bc7beeb103855a7a11dfb9f",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "293e5ce4ce54ee71990ab06e511b7ccd62722b1beb414f5ff65c8274e0f5be1d",
            "A quick movement of the enemy will jeopardize six gunboats." to "5d1edb7e9ace8dfef5319fdfd668052f4f9c55aaa2ad6bf48f548a394ad06fcd",
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an." to "565a2bc5616bfc4deff2d961ab299864206588854f9e707a6ec9dbd8d0a3886c"
        ),
        "SHA3-384" to mapOf(
            "a" to "1815f774f320491b48569efec794d249eeb59aae46d22bf77dafe25c5edc28d7ea44f93ee1234aa88f61c91912a4ccd9",
            "abc" to "ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
            "abcdefghijklmnopqrstuvwxyz" to "fed399d2217aaf4c717ad0c5102c15589e1c990cc2b9a5029056a7f7485888d6ab65db2370077a5cadb53fc9280d278f",
            "message digest" to "d9519709f44af73e2c8e291109a979de3d61dc02bf69def7fbffdfffe662751513f19ad57e17d4b93ba1e484fc1980d5",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "d5b972302f5080d0830e0de7b6b2cf383665a008f4c4f386a61112652c742d20cb45aa51bd4f542fc733e2719e999291",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "3c213a17f514638acb3bf17f109f3e24c16f9f14f085b52a2f2b81adc0db83df1a58db2ce013191b8ba72d8fae7e2a5e",
            "A quick movement of the enemy will jeopardize six gunboats." to "3701afe0781a502a9c8beb04a305d12c8bd88ae8b06e6adb656e352427152b81b06b9c7908749be2ecbe461c259c809e",
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an." to "68bc97d637f1d31398544ce92362caece0536701ec887793c407bbae7652cbdbf8d89e2897a2bc4e8f6982c35bdf527d"
        ),
        "SHA3-512" to mapOf(
            "a" to "697f2d856172cb8309d6b8b97dac4de344b549d4dee61edfb4962d8698b7fa803f4f93ff24393586e28b5b957ac3d1d369420ce53332712f997bd336d09ab02a",
            "abc" to "b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
            "abcdefghijklmnopqrstuvwxyz" to "af328d17fa28753a3c9f5cb72e376b90440b96f0289e5703b729324a975ab384eda565fc92aaded143669900d761861687acdc0a5ffa358bd0571aaad80aca68",
            "message digest" to "3444e155881fa15511f57726c7d7cfe80302a7433067b29d59a71415ca9dd141ac892d310bc4d78128c98fda839d18d7f0556f2fe7acb3c0cda4bff3a25f5f59",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" to "d1db17b4745b255e5eb159f66593cc9c143850979fc7a3951796aba80165aab536b46174ce19e3f707f0e5c6487f5f03084bc0ec9461691ef20113e42ad28163",
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890" to "9524b9a5536b91069526b4f6196b7e9475b4da69e01f0c855797f224cd7335ddb286fd99b9b32ffe33b59ad424cc1744f6eb59137f5fb8601932e8a8af0ae930",
            "A quick movement of the enemy will jeopardize six gunboats." to "e5bd78708a470098038dd81afe79d712910c0b7f00420126a94b0eb609bc1ae4b40874d37a828b064f1c8820e3e513affc779c9c34a710c67c8bd75a496b72b1",
            "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an." to "f213facfb400bb3c183663c94ae0ee6cc9561024c807aa7023940f9eed7f3d25297c8e74fe9faad70f391d1197933d9c59d7b63cd05bcb1608ce2ac30ea04b00",
            "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, " +
                    "sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit " +
                    "amet. Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, sed diam " +
                    "voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet." to
                    "3969d70c09e7455df937957a56bd6ade9b9e7df5ce072cc6ab33e63a4efbffa72852784e6f39d2cdc5cb2dc900995135bf8ba1649eaceadc902aa859678d0a6f"
        )
    )

    /** Additional inputs for boundary testing (empty + multi-block). */
    private val additionalReferenceInputs = listOf(
        "",
        "The quick brown fox jumps over the lazy dog",
        "a".repeat(1000)
    )

    @Nested
    @TestInstance(TestInstance.Lifecycle.PER_CLASS)
    inner class KnownAnswerTests {

        @ParameterizedTest(name = "{0}: \"{1}\"")
        @MethodSource("knownAnswerCases")
        fun `produces hash that matches official NIST and FIPS 202 test vectors`(algo: String, input: String, expected: String) {
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
        fun `produces identical hash to standard Java MessageDigest implementation`(algo: String, inputIndex: Int, input: String) {
            val hash = algorithms.first { it.jdkName == algo }.hash
            assertEquals(jdkHash(algo, input), hash(input), "Mismatch for $algo at index $inputIndex")
        }

        fun referenceCases(): List<Arguments> {
            val inputs = commonInputs + additionalReferenceInputs
            return algorithms.flatMap { alg ->
                inputs.mapIndexed { i, input -> Arguments.of(alg.jdkName, i, input) }
            }
        }
    }

    @Nested
    inner class EmptyInputTests {

        @Test
        fun `SHA3-224 produces correct hash for empty input according to FIPS 202`() {
            // TODO: Insert NIST/FIPS 202 known answer for SHA3-224("")
            assertEquals(jdkHash("SHA3-224", ""), SHA3.sha224(""))
        }

        @Test
        fun `SHA3-256 produces correct hash for empty input according to FIPS 202`() {
            assertEquals("a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a", SHA3.sha256(""))
        }

        @Test
        fun `SHA3-384 produces correct hash for empty input according to FIPS 202`() {
            // TODO: Insert NIST/FIPS 202 known answer for SHA3-384("")
            assertEquals(jdkHash("SHA3-384", ""), SHA3.sha384(""))
        }

        @Test
        fun `SHA3-512 produces correct hash for empty input according to FIPS 202`() {
            // TODO: Insert NIST/FIPS 202 known answer for SHA3-512("")
            assertEquals(jdkHash("SHA3-512", ""), SHA3.sha512(""))
        }
    }

    @Nested
    inner class PaddingBoundaryTests {

        @Test
        fun `all SHA3 variants produce correct hash for critical boundary lengths around block size`() {
            // SHA-3 block sizes per FIPS 202:
            // SHA3-224: 144, SHA3-256: 136, SHA3-384: 104, SHA3-512: 72
            for (algo in algorithms) {
                val blockSize = algo.blockSize
                val lengths = listOf(
                    0,
                    1,
                    blockSize - 2,
                    blockSize - 1,
                    blockSize,
                    blockSize + 1,
                    2 * blockSize - 1,
                    2 * blockSize,
                    2 * blockSize + 1
                )
                for (len in lengths) {
                    val msg = "x".repeat(len)
                    assertEquals(jdkHash(algo.jdkName, msg), algo.hash(msg),
                        "${algo.jdkName} mismatch for length $len")
                }
            }
        }
    }
}