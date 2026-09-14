package ai.rever.boss.services.totp

import java.io.ByteArrayOutputStream
import java.util.Locale

/**
 * Parses and builds `otpauth://` URIs - the payload every 2FA QR code carries and
 * the standard way an authenticator is enrolled (Key Uri Format, as used by Google
 * Authenticator and every compatible app).
 *
 * This is the enrolment half of TOTP: it turns a scanned or pasted URI into the
 * seed and parameters a generator needs, and turns those back into a URI for
 * export or for rendering a QR code. It is deliberately **self-contained** - it
 * does not depend on the code generator - so a caller maps [Algorithm] to its
 * generator's own by name.
 *
 * Kept pure and total: parsing is a function of the string alone, which is what
 * lets the awkward parts (a label of `issuer:account`, percent-encoding, the
 * `issuer` parameter vs the label prefix, HOTP's required counter) be pinned by
 * unit tests. The secret is a credential: it never appears in an exception
 * message and nothing here logs it.
 *
 * Scope note: decoding the QR *image* to a URI is the scanning surface's job (it
 * needs a camera or an image decoder); this is the correctness-critical core that
 * surface calls, where a mis-parsed period or a dropped issuer is exactly the kind
 * of bug a test must catch before a user relies on a code.
 */
object OtpauthUri {
    /** The two one-time-password kinds an `otpauth://` URI can name. */
    enum class Type {
        TOTP,
        HOTP,
    }

    /** Hash algorithms the `algorithm` parameter may name. */
    enum class Algorithm {
        SHA1,
        SHA256,
        SHA512,
    }

    /**
     * A parsed enrolment.
     *
     * [secret] is canonical Base32: uppercased, spaces removed, padding stripped.
     * [period] applies to TOTP and [counter] to HOTP; the other is left at its
     * default / null.
     */
    data class Credential(
        val type: Type,
        val secret: String,
        val issuer: String? = null,
        val accountName: String? = null,
        val algorithm: Algorithm = Algorithm.SHA1,
        val digits: Int = DEFAULT_DIGITS,
        val period: Int = DEFAULT_PERIOD,
        val counter: Long? = null,
    )

    const val DEFAULT_DIGITS = 6
    const val DEFAULT_PERIOD = 30
    private const val MAX_DIGITS = 10
    private const val SCHEME = "otpauth://"

    /**
     * Parse [uri], or throw with a message that never contains the secret.
     *
     * @throws IllegalArgumentException if the scheme, type or secret is missing or
     *   invalid, if a digit/period/counter value is not a positive number, or if a
     *   HOTP URI carries no counter.
     */
    fun parse(uri: String): Credential {
        val trimmed = uri.trim()
        require(trimmed.regionMatches(0, SCHEME, 0, SCHEME.length, ignoreCase = true)) {
            "not an otpauth:// URI"
        }
        val body = trimmed.substring(SCHEME.length)

        val queryStart = body.indexOf('?')
        val authorityAndPath = if (queryStart >= 0) body.substring(0, queryStart) else body
        val rawQuery = if (queryStart >= 0) body.substring(queryStart + 1) else ""

        val slash = authorityAndPath.indexOf('/')
        val typeToken = if (slash >= 0) authorityAndPath.substring(0, slash) else authorityAndPath
        val rawLabel = if (slash >= 0) authorityAndPath.substring(slash + 1) else ""

        val type =
            when (typeToken.lowercase(Locale.ROOT)) {
                "totp" -> Type.TOTP
                "hotp" -> Type.HOTP
                else -> throw IllegalArgumentException("unsupported otpauth type")
            }

        val params = parseQuery(rawQuery)
        val (labelIssuer, accountName) = parseLabel(rawLabel)

        val secret = canonicalSecret(params["secret"].orEmpty())
        // The issuer parameter is authoritative when present; the label prefix is
        // the fallback, since older generators only set one of the two.
        val issuer = params["issuer"]?.takeIf { it.isNotBlank() } ?: labelIssuer

        return Credential(
            type = type,
            secret = secret,
            issuer = issuer,
            accountName = accountName,
            algorithm = parseAlgorithm(params["algorithm"]),
            digits =
                parsePositive(params["digits"], DEFAULT_DIGITS, "digits").also {
                    require(it in 1..MAX_DIGITS) { "digits out of range" }
                },
            period = parsePositive(params["period"], DEFAULT_PERIOD, "period"),
            counter = parseCounter(type, params["counter"]),
        )
    }

    /** [parse] but returns null instead of throwing - for a paste field validating as the user types. */
    fun parseOrNull(uri: String): Credential? = runCatching { parse(uri) }.getOrNull()

    /**
     * Build the `otpauth://` URI for [credential], the inverse of [parse] for a
     * canonical credential (so `parse(build(c)) == c`).
     *
     * The issuer is written both into the label prefix and as the `issuer`
     * parameter, which is what QR generators do and what makes both readers agree.
     */
    fun build(credential: Credential): String {
        val type = credential.type.name.lowercase(Locale.ROOT)
        val label =
            buildString {
                credential.issuer?.let { append(encode(it)).append(':') }
                credential.accountName?.let { append(encode(it)) }
            }

        val params =
            buildList {
                add("secret=${credential.secret}")
                credential.issuer?.let { add("issuer=${encode(it)}") }
                add("algorithm=${credential.algorithm.name}")
                add("digits=${credential.digits}")
                when (credential.type) {
                    Type.TOTP -> add("period=${credential.period}")
                    Type.HOTP -> add("counter=${credential.counter ?: 0L}")
                }
            }

        return "$SCHEME$type/$label?${params.joinToString("&")}"
    }

    private fun parseAlgorithm(raw: String?): Algorithm =
        when (raw?.trim()?.uppercase(Locale.ROOT)) {
            null, "", "SHA1" -> Algorithm.SHA1
            "SHA256" -> Algorithm.SHA256
            "SHA512" -> Algorithm.SHA512
            else -> throw IllegalArgumentException("unsupported algorithm")
        }

    private fun parsePositive(
        raw: String?,
        default: Int,
        field: String,
    ): Int {
        if (raw.isNullOrBlank()) return default
        val value = raw.trim().toIntOrNull() ?: throw IllegalArgumentException("$field is not a number")
        require(value > 0) { "$field must be positive" }
        return value
    }

    private fun parseCounter(
        type: Type,
        raw: String?,
    ): Long? {
        if (type != Type.HOTP) return null
        val value = raw?.trim()?.toLongOrNull() ?: throw IllegalArgumentException("hotp requires a numeric counter")
        require(value >= 0) { "counter must not be negative" }
        return value
    }

    /** Split the label into its optional `issuer` prefix and account name, each decoded. */
    private fun parseLabel(rawLabel: String): Pair<String?, String?> {
        if (rawLabel.isEmpty()) return null to null
        val decoded = percentDecode(rawLabel)
        val colon = decoded.indexOf(':')
        // The spec allows an optional space after the colon.
        val issuer = if (colon < 0) null else decoded.substring(0, colon).trim().ifEmpty { null }
        val account = if (colon < 0) decoded.trim() else decoded.substring(colon + 1).trim()
        return issuer to account.ifEmpty { null }
    }

    private fun parseQuery(rawQuery: String): Map<String, String> {
        if (rawQuery.isBlank()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (pair in rawQuery.split('&')) {
            if (pair.isEmpty()) continue
            val eq = pair.indexOf('=')
            val key = if (eq >= 0) pair.substring(0, eq) else pair
            val value = if (eq >= 0) pair.substring(eq + 1) else ""
            // Keys are ASCII (secret/issuer/algorithm/digits/period/counter); only values are decoded.
            out[percentDecode(key).lowercase(Locale.ROOT)] = percentDecode(value)
        }
        return out
    }

    /** Uppercase, drop spaces and padding, and verify the Base32 alphabet. */
    private fun canonicalSecret(raw: String): String {
        val cleaned = raw.replace(" ", "").trimEnd('=').uppercase(Locale.ROOT)
        require(cleaned.isNotEmpty()) { "secret is missing" }
        require(cleaned.all { it in 'A'..'Z' || it in '2'..'7' }) { "secret is not valid Base32" }
        return cleaned
    }
}

private const val HEX_RADIX = 16
private const val PERCENT_LEN = 3
private const val UNRESERVED = "-._~"

/**
 * Decode `%XX` escapes as UTF-8, leaving `+` literal.
 *
 * `+` is deliberately not treated as a space: otpauth generators encode a space as
 * `%20`, and a literal `+` can appear in an account name.
 */
private fun percentDecode(value: String): String {
    if (!value.contains('%')) return value
    val bytes = ByteArrayOutputStream(value.length)
    var i = 0
    while (i < value.length) {
        val c = value[i]
        val hex =
            if (c == '%' && i + PERCENT_LEN <= value.length) {
                value.substring(i + 1, i + PERCENT_LEN).toIntOrNull(HEX_RADIX)
            } else {
                null
            }
        if (hex != null) {
            bytes.write(hex)
            i += PERCENT_LEN
        } else {
            bytes.write(c.toString().toByteArray(Charsets.UTF_8))
            i++
        }
    }
    return bytes.toByteArray().toString(Charsets.UTF_8)
}

/** Percent-encode a label/issuer value, keeping the RFC 3986 unreserved set. */
private fun encode(value: String): String =
    buildString {
        for (b in value.toByteArray(Charsets.UTF_8)) {
            val byte = b.toInt() and 0xFF
            val c = byte.toChar()
            val unreserved = c in 'A'..'Z' || c in 'a'..'z' || c in '0'..'9' || c in UNRESERVED
            if (unreserved) {
                append(c)
            } else {
                append('%').append(byte.toString(HEX_RADIX).uppercase(Locale.ROOT).padStart(2, '0'))
            }
        }
    }
