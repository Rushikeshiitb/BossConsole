package ai.rever.boss.services.security

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins [VaultBackup] and its [VaultCrypto] envelope. A round trip alone would not
 * prove the security properties, so this also checks that a wrong passphrase and a
 * tampered file both fail loudly (the GCM tag), and that two exports of the same
 * data differ (fresh salt and IV).
 */
class VaultBackupTest {
    private val entries =
        listOf(
            BackupEntry("https://example.com", "john", "hunter2", notes = "primary"),
            BackupEntry("https://bank.example", "jane", "s3cr3t!", notes = null),
        )
    private val passphrase = "correct horse battery staple".toCharArray()

    @Test
    fun `export then import round-trips the entries`() {
        val blob = VaultBackup.export(entries, passphrase)
        assertEquals(entries, VaultBackup.import(blob, passphrase))
    }

    @Test
    fun `an empty vault round-trips`() {
        val blob = VaultBackup.export(emptyList(), passphrase)
        assertTrue(VaultBackup.import(blob, passphrase).isEmpty())
    }

    @Test
    fun `a wrong passphrase is rejected, not silently wrong`() {
        val blob = VaultBackup.export(entries, passphrase)
        assertFailsWith<VaultBackupException> {
            VaultBackup.import(blob, "wrong passphrase".toCharArray())
        }
    }

    @Test
    fun `a tampered file fails the authentication tag`() {
        val blob = VaultBackup.export(entries, passphrase)
        // Flip a bit in the last byte (inside the ciphertext/tag).
        blob[blob.size - 1] = (blob[blob.size - 1].toInt() xor 0x01).toByte()
        assertFailsWith<VaultBackupException> { VaultBackup.import(blob, passphrase) }
    }

    @Test
    fun `bytes that are not a backup are refused`() {
        assertFailsWith<VaultBackupException> { VaultBackup.import("not a backup".toByteArray(), passphrase) }
        assertFailsWith<VaultBackupException> { VaultBackup.import(ByteArray(4), passphrase) }
    }

    @Test
    fun `two exports of the same data differ - fresh salt and IV`() {
        val a = VaultBackup.export(entries, passphrase)
        val b = VaultBackup.export(entries, passphrase)
        assertFalse(a.contentEquals(b), "IV/salt reuse would make exports identical")
    }

    @Test
    fun `the envelope starts with the BOSSVLT magic`() {
        val blob = VaultBackup.export(entries, passphrase)
        assertContentEquals("BOSSVLT".toByteArray(Charsets.US_ASCII), blob.copyOfRange(0, 7))
    }

    @Test
    fun `VaultCrypto round-trips arbitrary bytes`() {
        val payload = ByteArray(64) { it.toByte() }
        val blob = VaultCrypto.encrypt(payload, passphrase)
        assertContentEquals(payload, VaultCrypto.decrypt(blob, passphrase))
    }
}
