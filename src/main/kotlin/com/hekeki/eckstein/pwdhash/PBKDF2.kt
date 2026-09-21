/**
 * PBKDF2 - Generate PBKDF2 hash
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
package com.hekeki.eckstein.pwdhash

import com.hekeki.eckstein.mac.HMAC
import com.hekeki.eckstein.utils.Utils
import java.nio.charset.Charset
import kotlin.experimental.xor

object PBKDF2 {

    const val HMAC_SHA224 = "sha224"
    const val HMAC_SHA256 = "sha256"
    const val HMAC_SHA384 = "sha384"
    const val HMAC_SHA512 = "sha512"

    @JvmOverloads
    fun hash(prf: String, password: String, salt: ByteArray, iterations: Int, dkLen: Int, charset: Charset = Charsets.UTF_8): ByteArray {

        return when (prf) {
            HMAC_SHA224 -> pbkdf2(password.toByteArray(charset), salt, iterations, dkLen, 28, HMAC::sha224)
            HMAC_SHA256 -> pbkdf2(password.toByteArray(charset), salt, iterations, dkLen, 32, HMAC::sha256)
            HMAC_SHA384 -> pbkdf2(password.toByteArray(charset), salt, iterations, dkLen, 48, HMAC::sha384)
            HMAC_SHA512 -> pbkdf2(password.toByteArray(charset), salt, iterations, dkLen, 64, HMAC::sha512)
            else -> throw IllegalArgumentException("pseudorandom function $prf is not supported")
        }
    }

    @JvmOverloads
    fun verify(prf: String, password: String, hashed: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int, charset: Charset = Charsets.UTF_8): Boolean {

        val verify = hash(prf, password, salt, iterations, dkLen, charset)

        var diff = verify.size xor hashed.size
        var i = 0
        while (i < verify.size && i < hashed.size) {
            diff = diff or (verify[i].toInt() xor hashed[i].toInt())
            i++
        }
        return diff == 0
    }

    fun salt(size: Int): ByteArray = Utils.randomBytes(size)

    fun pbkdf2(password: ByteArray, salt: ByteArray, iterations: Int, dkLen: Int, hLen: Int, hmacFunction: (key: ByteArray, message: ByteArray) -> ByteArray): ByteArray {

        require(iterations > 0) { "iterations must be positive, but was $iterations" }
        require(dkLen > 0) { "dkLen must be positive, but was $dkLen" }
        if (dkLen > (Math.pow(2.0, 32.0) - 1) * hLen) {
            throw IllegalArgumentException("derived key is too long")
        }

        val l = ceil(dkLen, hLen)
        val r = dkLen - (l - 1) * hLen
        val t = ByteArray(l * hLen)
        var offset = 0

        for (blockNum in 1..l) {
            f(t, password, hmacFunction, salt, iterations, blockNum, offset, hLen)
            offset += hLen
        }

        if (r < hLen) {
            val derivedKey = ByteArray(dkLen)
            System.arraycopy(t, 0, derivedKey, 0, dkLen)
            return derivedKey
        }
        return t
    }

    private fun ceil(a: Int, b: Int): Int {
        val erg = a / b
        return if (a % b > 0) {
            erg + 1
        } else erg
    }

    private fun int(dest: ByteArray, offset: Int, i: Int) {
        dest[offset + 0] = (i shr 24 and 0xff).toByte()
        dest[offset + 1] = (i shr 16 and 0xff).toByte()
        dest[offset + 2] = (i shr 8 and 0xff).toByte()
        dest[offset + 3] = (i shr 0 and 0xff).toByte()
    }

    private fun xor(dest: ByteArray, src: ByteArray) {
        for (i in dest.indices) {
            dest[i] = dest[i] xor src[i]
        }
    }

    private fun f(dest: ByteArray, password: ByteArray, hmacFunction: (key: ByteArray, message: ByteArray) -> ByteArray, salt: ByteArray, iterations: Int, index: Int, offset: Int, hLen: Int) {

        val uc = ByteArray(hLen)
        var ui = salt.copyOf(salt.size + 4)
        int(ui, salt.size, index)

        for (i in 0 until iterations) {
            ui = hmacFunction(password, ui)
            xor(uc, ui)
        }
        System.arraycopy(uc, 0, dest, offset, hLen)
    }
}