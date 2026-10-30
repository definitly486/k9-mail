package com.fsck.k9.preferences

import assertk.assertFailure
import assertk.assertThat
import assertk.assertions.isEqualTo
import assertk.assertions.isFalse
import assertk.assertions.isInstanceOf
import assertk.assertions.isTrue
import kotlin.test.Test

class SettingsCryptoTest {
    private val plain = "<k9settings>secret</k9settings>".toByteArray()

    @Test
    fun `encrypt then decrypt returns original data`() {
        val encrypted = SettingsCrypto.encrypt(plain, "correct horse")

        assertThat(SettingsCrypto.isEncrypted(encrypted)).isTrue()
        assertThat(SettingsCrypto.decrypt(encrypted, "correct horse").toList()).isEqualTo(plain.toList())
    }

    @Test
    fun `decrypt with wrong passphrase fails`() {
        val encrypted = SettingsCrypto.encrypt(plain, "correct horse")

        assertFailure { SettingsCrypto.decrypt(encrypted, "wrong") }.isInstanceOf<SettingsDecryptionException>()
    }

    @Test
    fun `plain data is passed through when preparing for import`() {
        assertThat(SettingsCrypto.isEncrypted(plain)).isFalse()
        val result = SettingsCrypto.prepareForImport(plain.inputStream(), passphrase = null).readBytes()

        assertThat(result.toList()).isEqualTo(plain.toList())
    }

    @Test
    fun `encrypted data requires passphrase`() {
        val encrypted = SettingsCrypto.encrypt(plain, "correct horse")

        assertFailure {
            SettingsCrypto.prepareForImport(encrypted.inputStream(), passphrase = null)
        }.isInstanceOf<SettingsPassphraseRequiredException>()
    }
}
