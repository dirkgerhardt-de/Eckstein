/**
 * RSA - Encryption and decryption with RSA
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
package com.hekeki.eckstein.pubkey

import com.hekeki.eckstein.hash.SHA2
import com.hekeki.eckstein.utils.Utils
import java.math.BigInteger
import java.security.SecureRandom
import java.util.*

object RSA {

    enum class RSAES {
        OAEP,
        PKCS1
    }

    enum class SIGH(SIGH_PREFIX: ByteArray) {
        SHA224(SHA224_PREFIX),
        SHA256(SHA256_PREFIX),
        SHA384(SHA384_PREFIX),
        SHA512(SHA512_PREFIX);

        val prefix = SIGH_PREFIX
    }

    fun keyPair(keySize: Int) : RSAKeyPair {

        val primes = choosePrimes(keySize)
        val p = primes[0]
        val q = primes[1]
        val n = p.multiply(q)
        val phi = lcm(p.subtract(BigInteger.ONE), q.subtract(BigInteger.ONE))
        val e = BigInteger.valueOf(65537)
        val d = e.modInverse(phi)
        val exp1 = d.mod(p.subtract(BigInteger.ONE))
        val exp2 = d.mod(q.subtract(BigInteger.ONE))
        val coe = q.modInverse(p)

        return RSAKeyPair(RSAPublicKey(n, e), RSAPrivateKey(n, e, d, p, q, exp1, exp2, coe, phi))
    }

    fun encrypt(plainText: ByteArray, publicKey: RSAPublicKey, es: RSAES = RSAES.PKCS1): ByteArray {

        if(RSAES.PKCS1 == es) {
            return encryptPKCS1(plainText, publicKey)
        }
        throw IllegalArgumentException("Encryption scheme is not supported")
    }

    fun decrypt(encrypted: ByteArray, privateKey: RSAPrivateKey, es: RSAES = RSAES.PKCS1): ByteArray {

        if(RSAES.PKCS1 == es) {
            return decryptPKCS1(encrypted, privateKey)
        }
        throw IllegalArgumentException("Decryption scheme is not supported")
    }

    fun sign(message: ByteArray, privateKey: RSAPrivateKey, sigh: SIGH = SIGH.SHA256): ByteArray {

        val em = emsaPkcs1Encode(message, privateKey.k, sigh)
        val hm = os2ip(em)
        val sm = rsasp1(privateKey, hm)
        return i2osp(sm, privateKey.k)
    }

    fun verify(message: ByteArray, signed: ByteArray, publicKey: RSAPublicKey, sigh: SIGH = SIGH.SHA256): Boolean {

        val s = os2ip(signed)
        val m = rsavp1(publicKey, s)
        val em = i2osp(m, publicKey.k)
        val empkcs = emsaPkcs1Encode(message, publicKey.k, sigh)
        return Arrays.equals(em, empkcs)
    }

    private fun encryptPKCS1(message: ByteArray, publicKey: RSAPublicKey): ByteArray {

        if(message.size > publicKey.k - 11) {
            throw IllegalArgumentException("message to long")
        }

        val padding = randomNonZeroBytes(publicKey.k - message.size - 3)
        val encoded = encode(padding, message)
        val bi = os2ip(encoded)
        val encrypted = encryptBlock(bi, publicKey)

        return i2osp(encrypted, publicKey.k)
    }

    private fun decryptPKCS1(encrypted: ByteArray, privateKey: RSAPrivateKey): ByteArray {

        if(encrypted.size != privateKey.k || privateKey.k < 11) {
            throw IllegalArgumentException("decryption error")
        }

        val c = os2ip(encrypted)
        val pm = decryptBlock(c, privateKey)
        val m = i2osp(pm, privateKey.k)
        return decode(m)
    }

    private fun choosePrimes(keySize: Int): Array<BigInteger> {

        val primes = Array<BigInteger>(2) {BigInteger.ZERO}

        val p = getPrime(keySize)
        var q = getPrime(keySize)
        while (p == q) {
            q = getPrime(keySize)
        }

        if(p.subtract(q) < BigInteger.ZERO) {
            primes[0] = q
            primes[1] = p
        } else {
            primes[0] = p
            primes[1] = q
        }

        return primes
    }

    private fun getPrime(size: Int): BigInteger {
        val rnd = SecureRandom()
        var value = BigInteger.probablePrime(size / 2, rnd)
        while(!value.isProbablePrime(10)) {
            value = BigInteger.probablePrime(size / 2, rnd)
        }
        return value
    }

    private fun lcm(a: BigInteger, b: BigInteger): BigInteger {
        return (a.multiply(b).divide(a.gcd(b)))
    }

    private fun encode(padding: ByteArray, message: ByteArray) : ByteArray {
        val encoded = ByteArray(padding.size + message.size + 3)
        encoded[0] = 0x00
        encoded[1] = 0x02
        System.arraycopy(padding, 0, encoded, 2, padding.size)
        encoded[padding.size+2] = 0x00
        System.arraycopy(message, 0, encoded, padding.size+3, message.size)
        return encoded
    }

    private fun randomNonZeroBytes(size: Int): ByteArray {
        val result = Utils.randomBytes(size)
        for (i in result.indices) {
            while (result[i] == 0x00.toByte()) {
                result[i] = Utils.randomBytes(1)[0]
            }
        }
        return result
    }

    private fun decode(message: ByteArray) : ByteArray {
        // EB = 0x00 || 0x02 || PS (nonzero octets) || 0x00 || D
        if (message.size < 11 || message[0] != 0x00.toByte() || message[1] != 0x02.toByte()) {
            throw IllegalArgumentException("decryption error")
        }
        var index = 2
        while (index < message.size && message[index] != 0x00.toByte()) {
            index++
        }
        if (index == message.size) {
            throw IllegalArgumentException("decryption error")
        }
        return message.copyOfRange(index + 1, message.size)
    }

    private fun encryptBlock(m: BigInteger, publicKey: RSAPublicKey): BigInteger {
        return m.modPow(publicKey.e, publicKey.n)
    }

    private fun decryptBlock(m: BigInteger, privateKey: RSAPrivateKey): BigInteger {
        return m.modPow(privateKey.d, privateKey.n)
    }

    private fun rsasp1(privateKey: RSAPrivateKey, message: BigInteger): BigInteger {
        if(message < BigInteger.ZERO || message > privateKey.n.subtract(BigInteger.ONE)) {
            throw IllegalArgumentException("message representative out of range")
        }
        return message.modPow(privateKey.d, privateKey.n)
    }

    private fun rsavp1(publicKey: RSAPublicKey, signedMessage: BigInteger): BigInteger {
        if(signedMessage < BigInteger.ZERO || signedMessage > publicKey.n.subtract(BigInteger.ONE)) {
            throw IllegalArgumentException("signature representative out of range")
        }
        return signedMessage.modPow(publicKey.e, publicKey.n)
    }

    private fun emsaPkcs1Encode(message: ByteArray, emLen: Int, sigh: SIGH): ByteArray {

        val mHash = hash(message, sigh)

        val t = ByteArray(sigh.prefix.size + mHash.size)
        System.arraycopy(sigh.prefix, 0, t, 0, sigh.prefix.size)
        System.arraycopy(mHash, 0, t, sigh.prefix.size, mHash.size)

        val tLen = t.size
        if (emLen < tLen + 11) {
            throw IllegalArgumentException ("emLen too short")
        }

        val ps = ByteArray(emLen - tLen - 3)
        for (i in ps.indices) {
            ps[i] = 0xFF.toByte()
        }

        val result = ByteArray(3 + ps.size + tLen)
        result[0] = 0x00
        result[1] = 0x01
        System.arraycopy(ps, 0, result, 2, ps.size)
        result[ps.size+2] = 0x00
        System.arraycopy(t, 0, result, ps.size+3, t.size)
        return result
    }

    private fun hash(message: ByteArray, sigh: RSA.SIGH): ByteArray {
        return when (sigh) {
            SIGH.SHA224 -> SHA2.sha224(message)
            SIGH.SHA256 -> SHA2.sha256(message)
            SIGH.SHA384 -> SHA2.sha384(message)
            SIGH.SHA512 -> SHA2.sha512(message)
        }
    }

    private fun os2ip(bi: ByteArray): BigInteger {
        var out = BigInteger.ZERO
        val max = BigInteger("256")

        for (i in 1..bi.size) {
            out = out.add(BigInteger.valueOf((0xFF and bi[i - 1].toInt()).toLong()).multiply(max.pow(bi.size - i)))
        }
        return out
    }

    internal fun i2osp(bi: BigInteger, len: Int): ByteArray {
        val twofiftysix = BigInteger("256")
        val out = ByteArray(len)
        var cur: Array<BigInteger>

        if (bi >= twofiftysix.pow(len)) {
            throw IllegalArgumentException("integer to large")
        }

        for (i in 1..len) {
            cur = bi.divideAndRemainder(twofiftysix.pow(len - i))
            out[i - 1] = cur[0].toByte()
        }
        return out
    }

    private val SHA224_PREFIX = byteArrayOf(
            0x30.toByte(), 0x2d.toByte(), 0x30.toByte(), 0x0d.toByte(), 0x06.toByte(), 0x09.toByte(), 0x60.toByte(),
            0x86.toByte(), 0x48.toByte(), 0x01.toByte(), 0x65.toByte(), 0x03.toByte(), 0x04.toByte(), 0x02.toByte(),
            0x04.toByte(), 0x05.toByte(), 0x00.toByte(), 0x04.toByte(), 0x1c.toByte()
    )

    private val SHA256_PREFIX = byteArrayOf(
            0x30.toByte(), 0x31.toByte(), 0x30.toByte(), 0x0d.toByte(), 0x06.toByte(), 0x09.toByte(), 0x60.toByte(),
            0x86.toByte(), 0x48.toByte(), 0x01.toByte(), 0x65.toByte(), 0x03.toByte(), 0x04.toByte(), 0x02.toByte(),
            0x01.toByte(), 0x05.toByte(), 0x00.toByte(), 0x04.toByte(), 0x20.toByte()
    )

    private val SHA384_PREFIX = byteArrayOf(
            0x30.toByte(), 0x41.toByte(), 0x30.toByte(), 0x0d.toByte(), 0x06.toByte(), 0x09.toByte(), 0x60.toByte(),
            0x86.toByte(), 0x48.toByte(), 0x01.toByte(), 0x65.toByte(), 0x03.toByte(), 0x04.toByte(), 0x02.toByte(),
            0x02.toByte(), 0x05.toByte(), 0x00.toByte(), 0x04.toByte(), 0x30.toByte()
    )

    private val SHA512_PREFIX = byteArrayOf(
            0x30.toByte(), 0x51.toByte(), 0x30.toByte(), 0x0d.toByte(), 0x06.toByte(), 0x09.toByte(), 0x60.toByte(),
            0x86.toByte(), 0x48.toByte(), 0x01.toByte(), 0x65.toByte(), 0x03.toByte(), 0x04.toByte(), 0x02.toByte(),
            0x03.toByte(), 0x05.toByte(), 0x00.toByte(), 0x04.toByte(), 0x40.toByte()
    )
}
