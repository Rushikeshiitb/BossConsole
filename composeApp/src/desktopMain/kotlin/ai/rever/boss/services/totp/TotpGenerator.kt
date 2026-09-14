package ai.rever.boss.services.totp

import java.util.Locale
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.experimental.and

/**
 * RFC 6238 TOTP (and its RFC 4226 HOTP core), so BOSS can turn a stored 2FA seed
 * (`SecretMetadata.twofaSecret`) into the current 6-digit code - the piece a
 * "fill my authenticator code" affordance needs.
 *
 * Kept deliberately pure and injectable-clock: the code is a function of
 * `(secret, time, params)` only, which is what lets it be pinned against the
 * published RFC 6238 Appendix B test vectors with no mocking. The seed never
 * leaves this process, and nothing here logs it.
 *
 * Scope note: this generates the code. Placing it into a page's 2FA field is the
 * integrated browser's job (a separate surface); this is the correctness-critical
 * core that surface would call, and the reason it lives here is that getting HOTP
 * truncation or Base32 padding subtly wrong is exactly the kind of bug a unit
 * test must catch before a user ever relies on a code.
 */
object TotpGenerator {
    /** Hash algorithms an `otpauth://` URI may name. */
    enum class Algorithm(
        val macName: String,
    ) {
        SHA1("HmacSHA1"),
        SHA256("HmacSHA256"),
        SHA512("HmacSHA512"),
    }

    data class Params(
        val algorithm: Algorithm = Algorithm.SHA1,
        val digits: Int = 6,
        val periodSeconds: Long = 30L,
    )

    /**
     * The TOTP code for [base32Secret] at [unixTimeSeconds] (default: now).
     *
     * @throws IllegalArgumentException if the secret is not valid Base32 or the
     *   parameters are out of range - a bad seed must fail loudly here, not
     *   silently emit a code that will never match.
     */
    fun code(
        base32Secret: String,
        unixTimeSeconds: Long = System.currentTimeMillis() / 1000L,
        params: Params = Params(),
    ): String {
        require(params.digits in 1..9) { "digits must be 1..9" }
        require(params.periodSeconds > 0) { "period must be positive" }
        val key = base32Decode(base32Secret)
        require(key.isNotEmpty()) { "secret decoded to zero bytes" }
        val counter = Math.floorDiv(unixTimeSeconds, params.periodSeconds)
        return hotp(key, counter, params.algorithm, params.digits)
    }

    /**
     * RFC 4226 HOTP: HMAC over the 8-byte big-endian [counter], dynamic
     * truncation to a 31-bit integer, then modulo 10^digits, left-padded.
     */
    fun hotp(
        key: ByteArray,
        counter: Long,
        algorithm: Algorithm,
        digits: Int,
    ): String {
        val msg = ByteArray(8)
        var c = counter
        for (i in 7 downTo 0) {
            msg[i] = (c and 0xff).toByte()
            c = c ushr 8
        }

        val mac = Mac.getInstance(algorithm.macName)
        mac.init(SecretKeySpec(key, algorithm.macName))
        val hash = mac.doFinal(msg)

        // Dynamic truncation (RFC 4226 §5.3): low 4 bits of the last byte select
        // the offset; mask the top bit of the 4 taken bytes to stay positive.
        val offset = (hash[hash.size - 1] and 0x0f).toInt()
        val binary =
            ((hash[offset].toInt() and 0x7f) shl 24) or
                ((hash[offset + 1].toInt() and 0xff) shl 16) or
                ((hash[offset + 2].toInt() and 0xff) shl 8) or
                (hash[offset + 3].toInt() and 0xff)

        val otp = binary % POW10[digits]
        return otp.toString().padStart(digits, '0')
    }

    private val POW10 =
        IntArray(10).also {
            var v = 1
            for (i in 0..9) {
                it[i] = v
                v *= 10
            }
        }

    /**
     * Decode RFC 4648 Base32 (the authenticator seed encoding), ignoring spaces
     * and `=` padding and accepting either case.
     *
     * @throws IllegalArgumentException on a character outside the Base32 alphabet.
     */
    fun base32Decode(input: String): ByteArray {
        val cleaned =
            input
                .trim()
                .replace(" ", "")
                .trimEnd('=')
                .uppercase(Locale.ROOT)
        if (cleaned.isEmpty()) return ByteArray(0)

        val out = ArrayList<Byte>(cleaned.length * 5 / 8)
        var buffer = 0
        var bitsLeft = 0
        for (ch in cleaned) {
            val value = BASE32_ALPHABET.indexOf(ch)
            require(value >= 0) { "invalid Base32 character" }
            buffer = (buffer shl 5) or value
            bitsLeft += 5
            if (bitsLeft >= 8) {
                bitsLeft -= 8
                out.add(((buffer ushr bitsLeft) and 0xff).toByte())
            }
        }
        return out.toByteArray()
    }

    private const val BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
}
