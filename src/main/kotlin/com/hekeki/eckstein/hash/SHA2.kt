/**
 * SHA2 - Generate SHA2 hash
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

object SHA2 {

    fun sha224(message: ByteArray) = sha2(SHA2.VARIANT.SHA224, message)
    fun sha224(message: String) = Hex.encode(sha224(message.toByteArray()))

    fun sha256(message: ByteArray) = sha2(SHA2.VARIANT.SHA256, message)
    fun sha256(message: String) = Hex.encode(sha256(message.toByteArray()))

    fun sha384(message: ByteArray) = sha2(SHA2.VARIANT.SHA384, message)
    fun sha384(message: String) = Hex.encode(sha384(message.toByteArray()))

    fun sha512(message: ByteArray) = sha2(SHA2.VARIANT.SHA512, message)
    fun sha512(message: String) = Hex.encode(sha512(message.toByteArray()))

    private fun sha2(variant: VARIANT, msgBytes: ByteArray): ByteArray {

        // preprocessing
        val preprocessedMessage = preProcessing(variant, msgBytes)

        // processing
        return processMessage(variant, preprocessedMessage, preprocessedMessage.size)
    }

    private fun preProcessing(variant: VARIANT, msgBytes: ByteArray): ByteArray {
        val initialLen = msgBytes.size

        // always reserve one byte
        var newMessageLen = initialLen + 1
        while (newMessageLen % (variant.args()[1] / 8) != variant.args()[2] / 8) {
            newMessageLen++
        }

        // append "0" bit until message length
        val newMessage = msgBytes.copyOf(newMessageLen + variant.args()[3])

        // append "1" bit to message
        newMessage[msgBytes.size] = 0x80.toByte()

        //append original length in bits mod 264 to message
        toBytes(msgBytes.size * 8L, newMessage, variant.args()[3])

        return newMessage
    }

    private fun processMessage(variant: VARIANT, msg: ByteArray, len: Int): ByteArray {

        val chunks = len / variant.args()[4]

        var a = variant.h()[0]
        var b = variant.h()[1]
        var c = variant.h()[2]
        var d = variant.h()[3]
        var e = variant.h()[4]
        var f = variant.h()[5]
        var g = variant.h()[6]
        var h = variant.h()[7]
        var i = 0

        while (i < chunks) {
            val w = LongArray(variant.args()[5])

            for (j in 0 until variant.args()[5]) {
                when (j) {
                    in 0..15 -> {
                        w[j] = toLong(msg, i * variant.args()[4] + variant.args()[6] * j, variant.args()[6])
                    }

                    in 16 until variant.args()[5] -> {
                        val s0 = su(w[j - 15], variant.args()[7], variant.args()[13], w[j - 15], variant.args()[8], variant.args()[13], w[j - 15], variant.args()[9], variant)
                        val s1 = su(w[j - 2], variant.args()[10], variant.args()[13], w[j - 2], variant.args()[11], variant.args()[13], w[j - 2], variant.args()[12], variant)
                        w[j] = w[j - 16] + s0 + w[j - 7] + s1
                    }
                }
            }

            val originalA = a
            val originalB = b
            val originalC = c
            val originalD = d
            val originalE = e
            val originalF = f
            val originalG = g
            val originalH = h

            for (j in 0 until variant.args()[5]) {

                val s1 = sx(e, variant.args()[14], variant.args()[13], e, variant.args()[15], variant.args()[13], e, variant.args()[16], variant.args()[13], variant)
                val ch = (e and f) xor (e.inv() and g)
                val temp1 = h + s1 + ch + variant.k()[j] + w[j]
                val s0 = sx(a, variant.args()[17], variant.args()[13], a, variant.args()[18], variant.args()[13], a, variant.args()[19], variant.args()[13], variant)
                val maj = (a and b) xor (a and c) xor (b and c)
                val temp2 = s0 + maj

                h = g
                g = f
                f = e
                e = d + temp1
                d = c
                c = b
                b = a
                a = temp1 + temp2
            }

            a += originalA
            b += originalB
            c += originalC
            d += originalD
            e += originalE
            f += originalF
            g += originalG
            h += originalH

            i++
        }

        val raw = ByteArray(variant.args()[20])
        val k = variant.args()[6]
        val sv = variant.args()[21]
        val mult = variant.args()[22]
        val v = variant.args()[0]

        append(raw, a, 0 * mult, k, sv)
        append(raw, b, 4 * mult, k, sv)
        append(raw, c, 8 * mult, k, sv)
        append(raw, d, 12 * mult, k, sv)
        append(raw, e, 16 * mult, k, sv)
        append(raw, f, 20 * mult, k, sv)
        if (v != 384) {
            append(raw, g, 24 * mult, k, sv)
        }
        if (v == 256 || v == 512) {
            append(raw, h, 28 * mult, k, sv)
        }

        return raw
    }

    private fun append(hash: ByteArray, value: Long, offset: Int, k: Int, sv: Int) {
        for (j in 0 until k) {
            hash[j + offset] = (value.ushr(sv - j * 8) and 0xFF).toByte()
        }
    }

    private fun toLong(input: ByteArray, j: Int, k: Int): Long {
        var v: Long = 0
        for (i in 0 until k) {
            v = (v shl 8) + (input[i + j].toLong() and 0xff)
        }
        return v
    }

    private fun toBytes(value: Long, bytes: ByteArray, k: Int) {
        var va = value
        for (i in 1 until k) {
            bytes[bytes.size - i] = (va and 0x000000FF).toByte()
            va = va.ushr(8)
        }
    }

    private fun su(l: Long, i: Int, i1: Int, l1: Long, i2: Int, i3: Int, l2: Long, i4: Int, variant: VARIANT): Long {

        return if (variant.args()[0] == 224 || variant.args()[0] == 256) {
            (rightrotateInt(l.toInt(), i, i1) xor rightrotateInt(l1.toInt(), i2, i3) xor l2.toInt().ushr(i4)).toLong()
        } else {
            rightrotateLong(l, i, i1) xor rightrotateLong(l1, i2, i3) xor l2.ushr(i4)
        }
    }

    private fun sx(e: Long, i: Int, i1: Int, e1: Long, i2: Int, i3: Int, e2: Long, i4: Int, i5: Int, variant: SHA2.VARIANT): Long {

        return if (variant.args()[0] == 224 || variant.args()[0] == 256) {
            (rightrotateInt(e.toInt(), i, i1) xor rightrotateInt(e1.toInt(), i2, i3) xor rightrotateInt(e2.toInt(), i4, i5)).toLong()
        } else {
            rightrotateLong(e, i, i1) xor rightrotateLong(e1, i2, i3) xor rightrotateLong(e2, i4, i5)
        }
    }

    private fun rightrotateInt(num: Int, am: Int, si: Int): Int {
        return num.ushr(am) or (num shl si - am)
    }

    private fun rightrotateLong(num: Long, am: Int, si: Int): Long {
        return num.ushr(am) or (num shl si - am)
    }

    private enum class VARIANT {
        SHA224 {
            override fun args() = intArrayOf(224, 512, 448, 8, 64, 64, 4, 7, 18, 3, 17, 19, 10, 32, 6, 11, 25, 2, 13, 22, 28, 24, 1)
            override fun h() = longArrayOf(-0x3efa6128, 0x367cd507, 0x3070dd17, -0x8f1a6c7, -0x3ff4cf, 0x68581511, 0x64f98fa7, -0x4105b05c)
            override fun k() = SHA256.k()
        },
        SHA256 {
            override fun args() = intArrayOf(256, 512, 448, 8, 64, 64, 4, 7, 18, 3, 17, 19, 10, 32, 6, 11, 25, 2, 13, 22, 32, 24, 1)
            override fun h() = longArrayOf(0x6a09e667, -0x4498517b, 0x3c6ef372, -0x5ab00ac6, 0x510e527f, -0x64fa9774, 0x1f83d9ab, 0x5be0cd19)
            override fun k() = longArrayOf(
                0x428a2f98, 0x71374491, -0x4a3f0431, -0x164a245b, 0x3956c25b, 0x59f111f1, -0x6dc07d5c,
                -0x54e3a12b, -0x27f85568, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, -0x7f214e02, -0x6423f959, -0x3e640e8c,
                -0x1b64963f, -0x1041b87a, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, -0x67c1aeae,
                -0x57ce3993, -0x4ffcd838, -0x40a68039, -0x391ff40d, -0x2a586eb9, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138,
                0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, -0x7e3d36d2, -0x6d8dd37b, -0x5d40175f, -0x57e599b5, -0x3db47490,
                -0x3893ae5d, -0x2e6d17e7, -0x2966f9dc, -0xbf1ca7b, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
                0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, -0x7b3787ec, -0x7338fdf8, -0x6f410006,
                -0x5baf9315, -0x41065c09, -0x398e870e
            )
        },
        SHA384 {
            override fun args() = intArrayOf(384, 1024, 896, 16, 128, 80, 8, 1, 8, 7, 19, 61, 6, 64, 14, 18, 41, 28, 34, 39, 48, 56, 2)
            override fun h() = longArrayOf(
                -0x344462a23efa6128L, 0x629a292a367cd507L, -0x6ea6fea5cf8f22e9L,
                0x152fecd8f70e5939L, 0x67332667ffc00b31L, -0x714bb57897a7eaefL, -0x24f3d1f29b067059L, 0x47b5481dbefa4fa4L
            )

            override fun k() = SHA512.k()
        },
        SHA512 {
            override fun args() = intArrayOf(512, 1024, 896, 16, 128, 80, 8, 1, 8, 7, 19, 61, 6, 64, 14, 18, 41, 28, 34, 39, 64, 56, 2)
            override fun h() = longArrayOf(
                0x6A09E667F3BCC908L, -0x4498517a7b3558c5L, 0x3C6EF372FE94F82BL,
                -0x5ab00ac5a0e2c90fL, 0x510E527FADE682D1L, -0x64fa9773d4c193e1L, 0x1F83D9ABFB41BD6BL, 0x5BE0CD19137E2179L
            )

            override fun k() = longArrayOf(
                0x428A2F98D728AE22L, 0x7137449123EF65CDL, -0x4a3f043013b2c4d1L, -0x164a245a7e762444L,
                0x3956C25BF348B538L, 0x59F111F1B605D019L, -0x6dc07d5b50e6b065L, -0x54e3a12a25927ee8L, -0x27f855675cfcfdbeL,
                0x12835B0145706FBEL, 0x243185BE4EE4B28CL, 0x550C7DC3D5FFB4E2L, 0x72BE5D74F27B896FL, -0x7f214e01c4e9694fL,
                -0x6423f958da38edcbL, -0x3e640e8b3096d96cL, -0x1b64963e610eb52eL, -0x1041b879c7b0da1dL, 0x0FC19DC68B8CD5B5L,
                0x240CA1CC77AC9C65L, 0x2DE92C6F592B0275L, 0x4A7484AA6EA6E483L, 0x5CB0A9DCBD41FBD4L, 0x76F988DA831153B5L,
                -0x67c1aead11992055L, -0x57ce3992d24bcdf0L, -0x4ffcd8376704dec1L, -0x40a680384110f11cL, -0x391ff40cc257703eL,
                -0x2a586eb86cf558dbL, 0x06CA6351E003826FL, 0x142929670A0E6E70L, 0x27B70A8546D22FFCL, 0x2E1B21385C26C926L,
                0x4D2C6DFC5AC42AEDL, 0x53380D139D95B3DFL, 0x650A73548BAF63DEL, 0x766A0ABB3C77B2A8L, -0x7e3d36d1b812511aL,
                -0x6d8dd37aeb7dcac5L, -0x5d40175eb30efc9cL, -0x57e599b443bdcfffL, -0x3db4748f2f07686fL, -0x3893ae5cf9ab41d0L,
                -0x2e6d17e62910ade8L, -0x2966f9dbaa9a56f0L, -0xbf1ca7aa88edfd6L, 0x106AA07032BBD1B8L, 0x19A4C116B8D2D0C8L,
                0x1E376C085141AB53L, 0x2748774CDF8EEB99L, 0x34B0BCB5E19B48A8L, 0x391C0CB3C5C95A63L, 0x4ED8AA4AE3418ACBL,
                0x5B9CCA4F7763E373L, 0x682E6FF3D6B2B8A3L, 0x748F82EE5DEFB2FCL, 0x78A5636F43172F60L, -0x7b3787eb5e0f548eL,
                -0x7338fdf7e59bc614L, -0x6f410005dc9ce1d8L, -0x5baf9314217d4217L, -0x41065c084d3986ebL, -0x398e870d1c8dacd5L,
                -0x35d8c13115d99e64L, -0x2e794738de3f3df9L, -0x15258229321f14e2L, -0xa82b08011912e88L, 0x06F067AA72176FBAL,
                0x0A637DC5A2C898A6L, 0x113F9804BEF90DAEL, 0x1B710B35131C471BL, 0x28DB77F523047D84L, 0x32CAAB7B40C72493L,
                0x3C9EBE0A15C9BEBCL, 0x431D67C49C100D4CL, 0x4CC5D4BECB3E42B6L, 0x597F299CFC657E2AL, 0x5FCB6FAB3AD6FAECL,
                0x6C44198C4A475817L
            )
        };

        abstract fun args(): IntArray
        abstract fun h(): LongArray
        abstract fun k(): LongArray
    }
}