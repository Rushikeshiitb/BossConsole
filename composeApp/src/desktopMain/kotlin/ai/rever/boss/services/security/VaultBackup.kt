package ai.rever.boss.services.security

import kotlinx.serialization.Serializable
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.PBEKeySpec
import javax.crypto.spec.SecretKeySpec

/**
 * Encrypted, passphrase-protected vault export and import - backup and anti
 * lock-in, the two things a user fears about trusting a password manager.
 *
 * The file is a self-describing envelope so it can be read back by a future build:
 *
 * ```
 * "BOSSVLT" (7 bytes) | version (1) | salt (16) | iv (12) | AES-GCM ciphertext+tag
 * ```
 *
 * The passphrase is stretched with PBKDF2-HMAC-SHA256 over a fresh random salt, and
 * the payload is sealed with AES-256-GCM over a fresh random IV. GCM's authentication
 * tag is what makes a wrong passphrase and a tampered file both fail loudly on import
 * rather than returning garbage - the property this exists to guarantee and the one a
 * round-trip test alone would miss.
 */
class VaultBackupException(
    message: String,
    cause: Throwable? = null,
) : Exception(message, cause)

/** The AES-GCM + PBKDF2 envelope, independent of what is inside it. */
object VaultCrypto {
    private val MAGIC = "BOSSVLT".toByteArray(Charsets.US_ASCII)
    private const val VERSION: Byte = 1
    private const val SALT_LEN = 16
    private const val IV_LEN = 12
    private const val TAG_BITS = 128
    private const val KEY_BITS = 256
    private const val PBKDF2_ITERATIONS = 210_000
    private const val PBKDF2 = "PBKDF2WithHmacSHA256"
    private const val TRANSFORM = "AES/GCM/NoPadding"

    private val headerLen = MAGIC.size + 1
    private val minSize = headerLen + SALT_LEN + IV_LEN + TAG_BITS / 8
    private val secureRandom = SecureRandom()

    /** Seal [plaintext] under [passphrase], returning the complete envelope. */
    fun encrypt(
        plaintext: ByteArray,
        passphrase: CharArray,
    ): ByteArray {
        val salt = randomBytes(SALT_LEN)
        val iv = randomBytes(IV_LEN)
        val cipher = Cipher.getInstance(TRANSFORM)
        cipher.init(Cipher.ENCRYPT_MODE, deriveKey(passphrase, salt), GCMParameterSpec(TAG_BITS, iv))
        val ciphertext = cipher.doFinal(plaintext)
        return MAGIC + byteArrayOf(VERSION) + salt + iv + ciphertext
    }

    /**
     * Open an envelope produced by [encrypt].
     *
     * @throws VaultBackupException if the bytes are not a BOSS backup, or if the
     *   passphrase is wrong or the file was tampered with (GCM tag mismatch).
     */
    fun decrypt(
        blob: ByteArray,
        passphrase: CharArray,
    ): ByteArray {
        if (blob.size < minSize || !hasValidHeader(blob)) {
            throw VaultBackupException("not a BOSS vault backup")
        }
        val salt = blob.copyOfRange(headerLen, headerLen + SALT_LEN)
        val iv = blob.copyOfRange(headerLen + SALT_LEN, headerLen + SALT_LEN + IV_LEN)
        val ciphertext = blob.copyOfRange(headerLen + SALT_LEN + IV_LEN, blob.size)
        return runCatching {
            val cipher = Cipher.getInstance(TRANSFORM)
            cipher.init(Cipher.DECRYPT_MODE, deriveKey(passphrase, salt), GCMParameterSpec(TAG_BITS, iv))
            cipher.doFinal(ciphertext)
        }.getOrElse { throw VaultBackupException("wrong passphrase or corrupted backup", it) }
    }

    private fun hasValidHeader(blob: ByteArray): Boolean =
        blob.copyOfRange(0, MAGIC.size).contentEquals(MAGIC) && blob[MAGIC.size] == VERSION

    private fun deriveKey(
        passphrase: CharArray,
        salt: ByteArray,
    ): SecretKeySpec {
        val spec = PBEKeySpec(passphrase, salt, PBKDF2_ITERATIONS, KEY_BITS)
        try {
            val key = SecretKeyFactory.getInstance(PBKDF2).generateSecret(spec).encoded
            return SecretKeySpec(key, "AES")
        } finally {
            spec.clearPassword()
        }
    }

    private fun randomBytes(size: Int): ByteArray = ByteArray(size).also { secureRandom.nextBytes(it) }
}

/** One credential in a backup. Never logged; passwords live here in the clear only inside the envelope. */
@Serializable
data class BackupEntry(
    val website: String,
    val username: String,
    val password: String,
    val notes: String? = null,
)

/** Turns a list of credentials into an encrypted backup and back. */
object VaultBackup {
    private val json = Json { ignoreUnknownKeys = true }

    /** Serialise [entries] to JSON and seal them under [passphrase]. */
    fun export(
        entries: List<BackupEntry>,
        passphrase: CharArray,
    ): ByteArray = VaultCrypto.encrypt(json.encodeToString(entries).toByteArray(Charsets.UTF_8), passphrase)

    /**
     * Open a backup and parse its credentials.
     *
     * @throws VaultBackupException if decryption fails or the decrypted bytes are
     *   not a valid backup payload.
     */
    fun import(
        blob: ByteArray,
        passphrase: CharArray,
    ): List<BackupEntry> {
        val plaintext = VaultCrypto.decrypt(blob, passphrase).toString(Charsets.UTF_8)
        return runCatching { json.decodeFromString<List<BackupEntry>>(plaintext) }
            .getOrElse { throw VaultBackupException("backup contents are not valid", it) }
    }
}
