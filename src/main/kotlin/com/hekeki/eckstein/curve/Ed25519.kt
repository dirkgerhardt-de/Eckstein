/**
 * Ed25519 - Class to create Edwards-curve Digital Signature Algorithm (EdDSA) over Curve25519
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

import com.hekeki.eckstein.hash.SHA2
import com.hekeki.eckstein.utils.Utils
import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.Arrays

object Ed25519 {

    // based on Ref-Impl: https://ed25519.cr.yp.to/python/ed25519.py
    // scalarmult() uses extended homogeneous coordinates (RFC 8032, sec. 5.1.4)

    fun keyPair() : KeyPair {

        val privKey = Utils.randomBytes(32)
        val pubKey = publicKey(privKey)

        return KeyPair(PublicKey(pubKey), PrivateKey(privKey))
    }

    fun sign(message: ByteArray, keyPair: KeyPair): ByteArray {

        val h = hash(keyPair.privateKey.bytes)
        var a = BigInteger.valueOf(2).pow(b - 2)

        for (i in 3 until b - 2) {
            a = a.add(BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h, i).toLong())))
        }

        val rx = ByteBuffer.allocate(b / 8 + message.size)
        rx.put(h, b / 8, b / 4 - b / 8).put(message)

        val r = hint(rx.array())

        val r1 = scalarmult(B, r)
        val buffer = ByteBuffer.allocate(32 + keyPair.publicKey.bytes.size + message.size)
        buffer.put(encodepoint(r1)).put(keyPair.publicKey.bytes).put(message)
        val s = r.add(hint(buffer.array()).multiply(a)).mod(l)
        val res = ByteBuffer.allocate(64)
        res.put(encodepoint(r1)).put(encodeint(s))
        return res.array()
    }

    fun verify(signature: ByteArray, message: ByteArray, publicKey: PublicKey): Boolean {

        if (signature.size != b / 4) {
            throw IllegalArgumentException("signature length is wrong")
        }
        if (publicKey.bytes.size != b / 8) {
            throw IllegalArgumentException("public-key length is wrong")
        }

        val rBytes = Arrays.copyOfRange(signature, 0, b / 8)
        val r = decodepoint(rBytes)
        val a = decodepoint(publicKey.bytes)
        val sBytes = Arrays.copyOfRange(signature, b / 8, b / 4)
        val s = decodeint(sBytes)
        val buffer = ByteBuffer.allocate(32 + publicKey.bytes.size + message.size)
        buffer.put(encodepoint(r)).put(publicKey.bytes).put(message)
        val h = hint(buffer.array())
        val ra = scalarmult(B, s)
        val rb = edwards(r, scalarmult(a, h))

        return !(ra[0] != rb[0] || ra[1] != rb[1])
    }

    private fun hash(m: ByteArray): ByteArray {
        return SHA2.sha512(m)
    }

    private fun expmod(base: BigInteger, exponent: BigInteger, modulus: BigInteger): BigInteger {
        return base.modPow(exponent, modulus)
    }

    private fun inv(x: BigInteger): BigInteger {
        return expmod(x, qm2, q)
    }

    private fun xrecover(y: BigInteger): BigInteger {
        val y2 = y.multiply(y)
        val xx = y2.subtract(BigInteger.ONE).multiply(inv(d.multiply(y2).add(BigInteger.ONE)))
        var x = expmod(xx, qp3.divide(BigInteger.valueOf(8)), q)
        if (x.multiply(x).subtract(xx).mod(q) != BigInteger.ZERO) {
            x = x.multiply(I).mod(q)
        }
        if (x.mod(BigInteger.valueOf(2)) != BigInteger.ZERO) {
            x = q.subtract(x)
        }
        return x
    }

    private fun edwards(P: Array<BigInteger>, Q: Array<BigInteger>): Array<BigInteger> {
        val x1 = P[0]
        val y1 = P[1]
        val x2 = Q[0]
        val y2 = Q[1]
        val dx1x2y1y2 = d.multiply(x1).multiply(x2).multiply(y1).multiply(y2)
        val x3 = x1.multiply(y2).add(x2.multiply(y1)).multiply(inv(BigInteger.ONE.add(dx1x2y1y2)))
        val y3 = y1.multiply(y2).add(x1.multiply(x2)).multiply(inv(BigInteger.ONE.subtract(dx1x2y1y2)))
        return arrayOf(x3.mod(q), y3.mod(q))
    }

    private class ExtPoint(val x: BigInteger, val y: BigInteger, val z: BigInteger, val t: BigInteger)

    private fun toExt(P: Array<BigInteger>): ExtPoint {
        return ExtPoint(P[0], P[1], BigInteger.ONE, P[0].multiply(P[1]).mod(q))
    }

    /** Unified point addition "add-2008-hwcd-3" (a = -1): 9 field multiplications, no inversion. */
    private fun extAdd(p: ExtPoint, r: ExtPoint): ExtPoint {
        val a = p.y.subtract(p.x).multiply(r.y.subtract(r.x)).mod(q)
        val bb = p.y.add(p.x).multiply(r.y.add(r.x)).mod(q)
        val c = p.t.multiply(d2).multiply(r.t).mod(q)
        val dd = p.z.multiply(r.z).shiftLeft(1).mod(q)
        val e = bb.subtract(a)
        val f = dd.subtract(c)
        val g = dd.add(c)
        val h = bb.add(a)
        return ExtPoint(
            e.multiply(f).mod(q),
            g.multiply(h).mod(q),
            f.multiply(g).mod(q),
            e.multiply(h).mod(q)
        )
    }

    /** Point doubling "dbl-2008-hwcd" (a = -1): 4 field multiplications, no inversion. */
    private fun extDouble(p: ExtPoint): ExtPoint {
        val a = p.x.multiply(p.x).mod(q)
        val bb = p.y.multiply(p.y).mod(q)
        val c = p.z.multiply(p.z).mod(q).shiftLeft(1).mod(q)
        val h = a.add(bb)
        val xy = p.x.add(p.y)
        val e = h.subtract(xy.multiply(xy)).mod(q)
        val g = a.subtract(bb)
        val f = c.add(g)
        return ExtPoint(
            e.multiply(f).mod(q),
            g.multiply(h).mod(q),
            f.multiply(g).mod(q),
            e.multiply(h).mod(q)
        )
    }

    private fun scalarmult(P: Array<BigInteger>, e: BigInteger): Array<BigInteger> {

        // neutral element (0 : 1 : 1 : 0) in extended coordinates
        var acc = ExtPoint(BigInteger.ZERO, BigInteger.ONE, BigInteger.ONE, BigInteger.ZERO)
        var base = toExt(P)
        var ex = e

        while (ex.signum() > 0) {
            if (ex.testBit(0)) {
                acc = extAdd(acc, base)
            }
            ex = ex.shiftRight(1)
            if (ex.signum() > 0) {
                base = extDouble(base)
            }
        }

        val zInv = inv(acc.z)
        return arrayOf(acc.x.multiply(zInv).mod(q), acc.y.multiply(zInv).mod(q))
    }

    private fun encodeint(y: BigInteger): ByteArray {
        val result = ByteArray(b / 8)
        for (i in 0 until b) {
            if (y.testBit(i)) {
                result[i / 8] = (result[i / 8].toInt() or (1 shl (i % 8))).toByte()
            }
        }
        return result
    }

    private fun encodepoint(P: Array<BigInteger>): ByteArray {
        val x = P[0]
        val y = P[1]
        val res = encodeint(y)
        res[res.size - 1] = (res[res.size - 1].toInt() or (if (x.testBit(0)) 0x80 else 0)).toByte()
        return res
    }

    private fun bit(h: ByteArray, i: Int): Int {
        return h[i / 8].toInt() shr i % 8 and 1
    }

    internal fun publicKey(sk: ByteArray): ByteArray {
        val h = hash(sk)
        var a = BigInteger.valueOf(2).pow(b - 2)
        for (i in 3 until b - 2) {
            val ax = BigInteger.valueOf(2).pow(i).multiply(BigInteger.valueOf(bit(h, i).toLong()))
            a = a.add(ax)
        }
        val a1 = scalarmult(B, a)
        return encodepoint(a1)
    }

    private fun hint(m: ByteArray): BigInteger {
        val h = hash(m)
        val le = ByteArray(h.size)
        for (i in h.indices) {
            le[i] = h[h.size - 1 - i]
        }
        return BigInteger(1, le)
    }

    private fun isoncurve(P: Array<BigInteger>): Boolean {
        val x = P[0]
        val y = P[1]
        val xx = x.multiply(x)
        val yy = y.multiply(y)
        val dxxyy = d.multiply(yy).multiply(xx)
        return xx.negate().add(yy).subtract(BigInteger.ONE).subtract(dxxyy).mod(q) == BigInteger.ZERO
    }

    private fun decodeint(s: ByteArray): BigInteger {
        val res = ByteArray(s.size)
        for (i in s.indices) {
            res[i] = s[s.size - 1 - i]
        }
        return BigInteger(res).and(un)
    }

    private fun decodepoint(s: ByteArray): Array<BigInteger> {
        val bytes = ByteArray(s.size)
        for (i in s.indices) {
            bytes[i] = s[s.size - 1 - i]
        }
        val y = BigInteger(bytes).and(un)
        var x = xrecover(y)
        if ((if (x.testBit(0)) 1 else 0) != bit(s, b - 1)) {
            x = q.subtract(x)
        }
        val p = arrayOf(x, y)
        if (!isoncurve(p)) {
            throw IllegalArgumentException("decoding point that is not on curve")
        }
        return p
    }

    private const val b = 256
    private val q = BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819949")
    private val l = BigInteger("7237005577332262213973186563042994240857116359379907606001950938285454250989")
    private val d = BigInteger("-4513249062541557337682894930092624173785641285191125241628941591882900924598840740")
    private val d2 = d.shiftLeft(1).mod(q) // 2*d, used by extAdd()
    private val I = BigInteger("19681161376707505956807079304988542015446066515923890162744021073123829784752")
    private val By = BigInteger("46316835694926478169428394003475163141307993866256225615783033603165251855960")
    private val Bx = BigInteger("15112221349535400772501151409588531511454012693041857206046113283949847762202")
    private val un = BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819967")
    private val qm2 = BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819947")
    private val qp3 = BigInteger("57896044618658097711785492504343953926634992332820282019728792003956564819952")
    private val B = arrayOf(Bx.mod(q), By.mod(q))
}