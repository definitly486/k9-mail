package com.fsck.k9.preferences

import java.io.ByteArrayInputStream
import java.io.InputStream
import java.security.GeneralSecurityException
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Password based encryption for exported settings files.
 *
 * File format: `"K9ENC1"` | salt (16) | IV (12) | AES-256-GCM ciphertext + tag.
 * The key is derived with PBKDF2-HMAC-SHA256 (implemented on top of [Mac] because the JCA algorithm name is only
 * available on API 26+, while the app supports API 21+).
 */
object SettingsCrypto {
    private val MAGIC = "K9ENC1".toByteArray(Charsets.US_ASCII)
    private const val SALT_LENGTH = 16
    private const val IV_LENGTH = 12
    private const val TAG_BITS = 128
    private const val ITERATIONS = 200_000
    private const val HEADER_LENGTH = 6 + SALT_LENGTH + IV_LENGTH

    fun isEncrypted(data: ByteArray): Boolean {
        return data.size > HEADER_LENGTH && MAGIC.indices.all { data[it] == MAGIC[it] }
    }

    fun encrypt(plain: ByteArray, passphrase: String): ByteArray {
        val random = SecureRandom()
        val salt = ByteArray(SALT_LENGTH).also { random.nextBytes(it) }
        val iv = ByteArray(IV_LENGTH).also { random.nextBytes(it) }

        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(passphrase, salt), GCMParameterSpec(TAG_BITS, iv))
        cipher.updateAAD(MAGIC)

        return MAGIC + salt + iv + cipher.doFinal(plain)
    }

    @Throws(SettingsDecryptionException::class)
    fun decrypt(data: ByteArray, passphrase: String): ByteArray {
        if (!isEncrypted(data)) throw SettingsDecryptionException()

        try {
            val salt = data.copyOfRange(MAGIC.size, MAGIC.size + SALT_LENGTH)
            val iv = data.copyOfRange(MAGIC.size + SALT_LENGTH, HEADER_LENGTH)

            val cipher = Cipher.getInstance("AES/GCM/NoPadding")
            cipher.init(Cipher.DECRYPT_MODE, deriveKey(passphrase, salt), GCMParameterSpec(TAG_BITS, iv))
            cipher.updateAAD(MAGIC)

            return cipher.doFinal(data, HEADER_LENGTH, data.size - HEADER_LENGTH)
        } catch (e: GeneralSecurityException) {
            throw SettingsDecryptionException(e)
        }
    }

    /**
     * Returns a stream with the plain settings. Encrypted files are decrypted using [passphrase]; plain files are
     * passed through unchanged.
     */
    @Throws(SettingsPassphraseRequiredException::class, SettingsDecryptionException::class)
    fun prepareForImport(inputStream: InputStream, passphrase: String?): InputStream {
        val bytes = inputStream.readBytes()
        if (!isEncrypted(bytes)) return ByteArrayInputStream(bytes)
        if (passphrase.isNullOrEmpty()) throw SettingsPassphraseRequiredException()

        return ByteArrayInputStream(decrypt(bytes, passphrase))
    }

    // PBKDF2 with HMAC-SHA256, a single 32 byte block is enough for an AES-256 key.
    private fun deriveKey(passphrase: String, salt: ByteArray): SecretKeySpec {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(passphrase.toByteArray(Charsets.UTF_8), "HmacSHA256"))

        mac.update(salt)
        mac.update(byteArrayOf(0, 0, 0, 1))
        var u = mac.doFinal()
        val result = u.copyOf()

        repeat(ITERATIONS - 1) {
            u = mac.doFinal(u)
            for (i in result.indices) {
                result[i] = (result[i].toInt() xor u[i].toInt()).toByte()
            }
        }

        return SecretKeySpec(result, "AES")
    }
}

class SettingsPassphraseRequiredException : Exception("Settings file is encrypted, passphrase required")

class SettingsDecryptionException(cause: Throwable? = null) : Exception("Wrong passphrase or corrupted file", cause)
