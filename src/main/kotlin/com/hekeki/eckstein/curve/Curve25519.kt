/**
 * Curve25519 - Class to create Elliptic Curve Diffie-Hellman (ECDH) over Curve25519 (X25519)
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

import com.hekeki.eckstein.utils.Utils

object Curve25519 {

    fun keyPair() : KeyPair {

        val privKey = Utils.randomBytes(32)
        val pubKey = publicKey(privKey)

        return KeyPair(PublicKey(pubKey), PrivateKey(privKey))
    }

    fun sharedKey(myPrivateKey: PrivateKey, theirPublicKey: PublicKey): ByteArray {
        val privKey = clamp(myPrivateKey.bytes)
        return scalarMultiplication(privKey, theirPublicKey.bytes)
    }

    private fun publicKey(privateKey: ByteArray): ByteArray {
        val privKey = clamp(privateKey)
        return scalarMultiplication(privKey, BASE_POINT)
    }

    private fun clamp(key: ByteArray): ByteArray {
        val ckey = key.copyOf()
        ckey[31] = (ckey[31].toLong() and 0x7F).toByte()
        ckey[31] = (ckey[31].toLong() or 0x40).toByte()
        ckey[0] = (ckey[0].toLong() and 0xF8).toByte()
        return ckey
    }

    private fun scalarMultiplication(multiplier: ByteArray, multiplicand: ByteArray): ByteArray {

        val x = LongArray(80)

        val a = ONE.clone()
        val b = ZERO.clone()
        val c = ZERO.clone()
        val d = ONE.clone()
        val e = ZERO.clone()
        val f = ZERO.clone()

        val z = multiplier.clone()
        var r: Long

        unpack(x, multiplicand)
        copy(b, x)

        for (i in 254 downTo 0) {

            r = (z[i.ushr(3)].toLong().ushr(i and 7)) and 1
            sel25519(a, b, r)
            sel25519(c, d, r)
            add(e, a, c)
            sub(a, a, c)
            add(c, b, d)
            sub(b, b, d)
            sqr(d, e)
            sqr(f, a)
            mult(a, c, a)
            mult(c, b, e)
            add(e, a, c)
            sub(a, a, c)
            sqr(b, a)
            sub(c, d, f)
            mult(a, c, X121665)
            add(a, a, d)
            mult(c, c, a)
            mult(a, d, f)
            mult(d, b, x)
            sqr(b, e)
            sel25519(a, b, r)
            sel25519(c, d, r)
        }

        for (i in 0 until 16) {
            x[i + 16] = a[i]
            x[i + 32] = c[i]
            x[i + 48] = b[i]
            x[i + 64] = d[i]
        }

        val x32 = x.copyOfRange(32, x.size)
        inv25519(x32, x32)

        System.arraycopy(x32, 0, x, 32, x32.size)

        val x16 = x.copyOfRange(16, x.size)
        mult(x16, x16, x32)

        val result = ByteArray(32)
        pack(result, x16)

        return result
    }

    private fun unpack(result: LongArray, values: ByteArray) {
        for (i in 0 until 16) {
            result[i] = ((values[2 * i].toLong() and 0xFF) + ((values[2 * i + 1].toLong() and 0xFF) shl 8))
        }
        result[15] = result[15] and 0x7fff
    }

    private fun copy(dest: LongArray, src: LongArray) {
        val size = if(dest.size > src.size) src.size else dest.size
        for (i in 0 until size) {
            dest[i] = src[i]
        }
    }

    private fun sel25519(p: LongArray, q: LongArray, b: Long) {
        var t: Long
        val c = (b - 1).inv()
        for (i in 0..15) {
            t = c and (p[i] xor q[i])
            p[i] = (p[i] xor t)
            q[i] = (q[i] xor t)
        }
    }

    private fun add(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) {
            o[i] = (a[i] + b[i]) or 0
        }
    }

    private fun sub(o: LongArray, a: LongArray, b: LongArray) {
        for (i in 0 until 16) {
            o[i] = (a[i] - b[i]) or 0
        }
    }

    private fun sqr(o: LongArray, a: LongArray) {
        mult(o, a, a)
    }

    private fun mult(o: LongArray, a: LongArray, b: LongArray) {
        val t = LongArray(31)

        for (i in 0 until 16) {
            for (j in 0 until 16) {
                t[i+j] += a[i] * b[j]
            }
        }

        for (i in 0 until 15) {
            t[i] += 38 * t[i+16]
        }

        car25519(t)
        car25519(t)
        copy(o, t)
    }

    private fun car25519(o: LongArray) {
        var c: Long

        for (i in 0 until 16) {
            o[i] += (65536).toLong()
            c = Math.floor(o[i].toDouble() / 65536).toLong()
            o[(i + 1) * (if(i < 15) 1 else 0)] += c - 1 + 37 * (c-1) * (if(i == 15) 1 else 0)
            o[i] -= (c * 65536)
        }
    }

    private fun inv25519(o: LongArray, w: LongArray) {
        val c = LongArray(16)

        copy(c, w)

        for (i in 253 downTo 0) {
            sqr(c, c)
            if(i != 2 && i != 4) {
                mult(c, c, w)
            }
        }

        copy(o, c)
    }

    private fun pack(result: ByteArray, values: LongArray) {

        val m = LongArray(16)
        val tmp = LongArray(16)
        var c: Long

        copy(tmp, values)
        car25519(tmp)
        car25519(tmp)
        car25519(tmp)

        for (j in 0..1) {
            m[0] = tmp[0] - 0xFFED

            for (i in 1 until 15) {
                m[i] = tmp[i] - 0xFFFF - (m[i - 1] shr 16 and 1)
                m[i - 1] = m[i - 1] and 0xFFFF
            }

            m[15] = tmp[15] - 0x7FFF - (m[14] shr 16 and 1)
            c = m[15] shr 16 and 1
            m[14] = m[14] and 0xFFFF

            sel25519(tmp, m, 1 - c)
        }

        for (i in 0 until 16) {
            result[2 * i] = (tmp[i] and 0xFF).toByte()
            result[2 * i + 1] = (tmp[i] shr 8).toByte()
        }
    }

    private val ZERO = LongArray(16) { 0 }

    private val ONE: LongArray = LongArray(16) { i ->
        when (i) {
            0 -> 1
            else -> 0
        }
    }

    private val X121665: LongArray = LongArray(16) { i ->
        when(i) {
            0 -> 0xdb41
            1 -> 1
            else -> 0
        }
    }

    private val BASE_POINT: ByteArray = ByteArray(32) { i ->
        when (i) {
            0 -> 9
            else -> 0
        }
    }
}
