/**
 * HMACTest - Class to test HMAC function
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
package com.hekeki.eckstein.mac

import com.hekeki.eckstein.encoding.Hex
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Test
import java.nio.charset.StandardCharsets
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

class HMACTest {

    companion object {
        private const val KEY = "4469726B4765726861726474"
        private const val PANGRAM = "Schweißgequält zündet Typograf Jakob verflixt öde Pangramme an."
        private const val LONG_TEXT = "A quick movement of the enemy will jeopardize six gunboats."
        private val DIGITS_80 = "1234567890".repeat(8)
        private const val ALPHANUMERIC =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
        private const val LOREM_IPSUM =
            "Lorem ipsum dolor sit amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor " +
                    "invidunt ut labore et dolore magna aliquyam erat, sed diam voluptua. At vero eos et accusam et justo duo dolores et " +
                    "ea rebum. Stet clita kasd gubergren, no sea takimata sanctus est Lorem ipsum dolor sit amet. Lorem ipsum dolor sit " +
                    "amet, consetetur sadipscing elitr, sed diam nonumy eirmod tempor invidunt ut labore et dolore magna aliquyam erat, " +
                    "sed diam voluptua. At vero eos et accusam et justo duo dolores et ea rebum. Stet clita kasd gubergren, no sea " +
                    "takimata sanctus est Lorem ipsum dolor sit amet."
    }

    /** One HMAC variant with references to both overloads plus the JDK algorithm name. */
    private data class HmacVariant(
        val jdkAlgorithm: String,
        val raw: (ByteArray, ByteArray) -> String,
        val hex: (String, String) -> String
    )

    private val variants = listOf(
        HmacVariant("HmacSHA224", { k, m -> Hex.encode(HMAC.sha224(k, m)) }, { k, m -> HMAC.sha224Hex(k, m) }),
        HmacVariant("HmacSHA256", { k, m -> Hex.encode(HMAC.sha256(k, m)) }, { k, m -> HMAC.sha256Hex(k, m) }),
        HmacVariant("HmacSHA384", { k, m -> Hex.encode(HMAC.sha384(k, m)) }, { k, m -> HMAC.sha384Hex(k, m) }),
        HmacVariant("HmacSHA512", { k, m -> Hex.encode(HMAC.sha512(k, m)) }, { k, m -> HMAC.sha512Hex(k, m) })
    )

    private fun assertTestVectors(vectors: List<Pair<String, String>>, hmacHex: (String) -> String) =
        vectors.forEach { (message, expected) ->
            assertEquals(expected, hmacHex(message), "Failed for message: \"$message\"")
        }

    @Test
    fun `produces correct HMAC-SHA224 hash for all known test vectors`() = assertTestVectors(
        listOf(
            "a" to "2fb80dd1b9c39aece7090b06ecbfdac5f5cc720b80ed1c3950c04f3d",
            "abc" to "a00275b8df17da0259f95a99cad0a531bec74b63489064da88f9b876",
            "abcdefghijklmnopqrstuvwxyz" to "7697d174c25f10d2785d8c7cf3ffa176599be9c4991839e5c443081d",
            "message digest" to "8ffcabab0d46d2795f60e2ac6863245e434638736be10f3909adb52f",
            ALPHANUMERIC to "110eeb37da35c33dc3a75390b8c9fb50d8031d5a9870228cb6919015",
            DIGITS_80 to "c6f846f64537fc92d6d9a3043dc0bd8f1bc01925d948961e8ebdd044",
            LONG_TEXT to "d5ec898abfb8caad5ce6436eb6510dff5d038ae9e968523aad530e7f",
            PANGRAM to "ca1e7d17f1b44aa071320ac9c8facee45bc7d30c31c13ab285ab8494"
        )
    ) { HMAC.sha224Hex(KEY, it) }

    @Test
    fun `produces correct HMAC-SHA256 hash for all known test vectors`() = assertTestVectors(
        listOf(
            "a" to "ee5abdb1a95dc78c59c7feb9688eaf3947650d4fc1dc0283afc75bcd09cda45d",
            "abc" to "34ff7ba8b29202603bb5300d5c3c5b6f781ba8ac5e4f6d63404b2a75dbab77b9",
            "abcdefghijklmnopqrstuvwxyz" to "b191f1ee30396296370ae2a75396278c24b8997c32e9dee8fa307c032a9035e2",
            "message digest" to "1c5a20aaac95f9113f06a5e65bce998034917dabeca4f70d4e51fe8ca14b7f61",
            ALPHANUMERIC to "e436d05122707077d2ea9eda4eefd360fbd488dfa8464e8593f428453da74110",
            DIGITS_80 to "8accf28017c679b90f35cf93b55d6ea72dad8b35ca54fc52b21225e60a0d4a7b",
            LONG_TEXT to "c5f9fab7ab2b41c2a1a4fd4c5241f1de97beee260533c86e15bc63082a16bd6c",
            PANGRAM to "c98ab641a2c962f74198e19f7cc299ae33d2e13c121746d23e35f0b23f1cae06"
        )
    ) { HMAC.sha256Hex(KEY, it) }

    @Test
    fun `produces correct HMAC-SHA384 hash for all known test vectors`() = assertTestVectors(
        listOf(
            "a" to "88939bb17f51ed18aba4dc96c10b418441ce718367bac9410a6053eb96556d2d531b9c0f92aa73fcce41e82c3ef4f20f",
            "abc" to "b2baa22783312b967a97b1ef6c4568068bf17db5b521bf69da22355d85013bbbddb785d45f6c9c01afbe842be455c4e4",
            "abcdefghijklmnopqrstuvwxyz" to "07e9d9303b396417b35e8954e8480f281dcbc7f2f88775fc9604f5e24e9ff5221eb3e068b8110e657dfd33b91b813349",
            "message digest" to "3dcd62b5f490ec7e7f7589963b8bb18d8db2c9f3e0138e771005815863307459b7256a5d5041def7badc2f4a6ee547e2",
            ALPHANUMERIC to "a4bbe957e148cd31cbb00b77f81e21c24665e8fb4cc141491b7e60b71a5d903ea603b8724692c332aa66cf2619349701",
            DIGITS_80 to "26708458918b25e63a47b126852cb03b019846f8b73504c237352fcab0472b0cadc0c509b81e70b07797a79fd5015cfd",
            LONG_TEXT to "83e00937d92713cddc3958f0d08ed65c8376a2c84f7365cbc73b4d281a51233ee2d8fbd98951d1fbcd86122ed0578800",
            PANGRAM to "92beb094e5f0966cfbaedbae7ba4ccce323afa4de94eb5ca10a3a44a70ccead5a72ffb51a24ef4b5f0f5ca63ac03360f"
        )
    ) { HMAC.sha384Hex(KEY, it) }

    @Test
    fun `produces correct HMAC-SHA512 hash for all known test vectors`() = assertTestVectors(
        listOf(
            "a" to "ba76ae26b103b9e7ed33fe31eafd33d439031dc3c9f02626aeacd4eac26e27cece3cfdb1640ee0fcc6b013c4af18f38ea79d0851783cd86874d06dc98de000be",
            "abc" to "9a04ef3dc0e170403d57f849045864ae967c163bbfa6d4491298378ddb82bcf6548e35045ad267670b0d7ee6b7c7b2b917ebd6cb36409faab0649fe09c365471",
            "abcdefghijklmnopqrstuvwxyz" to "254c22a5a30017f067ffe3b221150b91db9847647a1c845ca681dec4e395ad19df1e3de56ac637f15571cdc8c382f82d92070f4da1d55ad2fa996b548ae56e6a",
            "message digest" to "c5f9e25552215c013bb84273ae1de4abd07bbd9bce50a82f4c99a7ef15ba192dd84496ffd6831c4c3a460afcf231b5eaaaafbf5b8a11d064d61026ecffd321bd",
            ALPHANUMERIC to "6307c492e552418815556ee863620632df38082495ce3c867a89b2db40d7a3df0b344a70a3f11e914b09d75a7d1ec3697b3d444ae39eb2db404afb78ebc39742",
            DIGITS_80 to "e488dd58c2b5aed55b81ea09b12fc077ed9bb85e5d42e31b5bff5a16a5c23384423d1af8198e62c08eac2af1cf9bd7a077ece872ffbbf2bbd9332b4c2b1d7199",
            LONG_TEXT to "7b7ba2c8385048a3bcdb0294269c56f705b9ce00f71349c3101e24b6d9c02effad79edd07f7c5d4910c6bf6222bb81912a7af9b6c6271b148f722ede27e96c93",
            PANGRAM to "e1dd4a9abbed6944fc2b0e39b4f162b29b6f96431c3b6083063e167ed649cc9093f853be492e326338972b5e76a820870e69beb9bedce7e8dd31dd16f882422c"
        )
    ) { HMAC.sha512Hex(KEY, it) }

    @Test
    fun `produces correct hash when processing large plaintext exceeding block size`() {
        assertEquals(
            "fb94ef3435ff1bfb010fb88088a111ea6bb1086148290ec5e20c27ff3cf55791b758205fde468b95591f4c60d59b5e3495e06a30dc1443b30388f093964258d1",
            HMAC.sha512Hex(KEY, LOREM_IPSUM)
        )
    }

    @Test
    fun `produces correct hash when key and message both exceed block size`() {
        assertEquals(
            "6f3dbfd27acb93dcb58533d26340c949ba68f037e520940d7d670afcc0d3fa6b",
            HMAC.sha256Hex(LOREM_IPSUM, PANGRAM)
        )
        assertEquals(
            "630ab05b3f6964014db021ec2c8b766b95adc20bc206fbb9f8b599493c66e5911e27c67506aa5ea0db36f63128fa64c97034e10620388cffb3194af3fe4b13fc",
            HMAC.sha512Hex(LOREM_IPSUM, PANGRAM)
        )
    }

    private fun jdkHmac(algorithm: String, key: ByteArray, message: ByteArray): String {
        val mac = Mac.getInstance(algorithm)
        mac.init(SecretKeySpec(key, algorithm))
        return Hex.encode(mac.doFinal(message))
    }

    private val keys = listOf("key", "a".repeat(10), "a".repeat(64), "a".repeat(65), "a".repeat(200))
    private val messages = listOf("", "The quick brown fox jumps over the lazy dog", "a".repeat(1000))

    @Test
    fun `matches JDK reference for all algorithms`() {
        for (variant in variants) for (key in keys) for (msg in messages) {
            val keyBytes = key.toByteArray()
            val msgBytes = msg.toByteArray()
            val expected = jdkHmac(variant.jdkAlgorithm, keyBytes, msgBytes)

            assertEquals(
                expected, variant.hex(key, msg),
                "${variant.jdkAlgorithm}: mismatch (string overload) for key.len=${key.length}, msg.len=${msg.length}"
            )
            assertEquals(
                expected, variant.raw(keyBytes, msgBytes),
                "${variant.jdkAlgorithm}: mismatch (ByteArray overload) for key.len=${key.length}, msg.len=${msg.length}"
            )
        }
    }

    @Test
    fun `raw and hex overloads are consistent for both String and ByteArray input`() {
        val key = "key"
        val msg = "message"
        val rawFromString = HMAC.sha256(key, msg)
        val rawFromBytes = HMAC.sha256(key.toByteArray(Charsets.UTF_8), msg.toByteArray(Charsets.UTF_8))
        assertArrayEquals(rawFromBytes, rawFromString)
        assertEquals(Hex.encode(rawFromString), HMAC.sha256Hex(key, msg))
        assertEquals(Hex.encode(rawFromBytes), HMAC.sha256Hex(key.toByteArray(), msg.toByteArray()))
    }

    @Test
    fun `charset parameter is honored for string overloads`() {
        val text = "Grüße"
        val iso = StandardCharsets.ISO_8859_1
        val expected = HMAC.sha256(text.toByteArray(iso), text.toByteArray(iso))
        assertArrayEquals(expected, HMAC.sha256(text, text, iso))
        assertEquals(Hex.encode(expected), HMAC.sha256Hex(text, text, iso))
    }

    @Test
    fun `empty key does not throw and is deterministic`() {
        val result1 = HMAC.sha256Hex("", "message")
        val result2 = HMAC.sha256Hex("", "message")
        assertEquals(result1, result2)
        assertEquals(64, result1.length) // SHA-256 hex output length
    }

    @Test
    fun `known RFC 4231 test vector for HMAC-SHA256`() {
        // RFC 4231 Test Case 1
        val key = ByteArray(20) { 0x0b }
        val data = "Hi There".toByteArray()
        assertEquals(
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
            HMAC.sha256Hex(key, data)
        )
    }
}