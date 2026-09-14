package ai.rever.boss.services.security

import ai.rever.boss.services.supabase.models.SecretEntry
import java.security.MessageDigest
import java.util.Locale

/**
 * Vault password health: the reuse / strength / breach analysis behind a
 * "Security" view over the user's own secrets, in the spirit of 1Password
 * Watchtower or Bitwarden's exposed-password report.
 *
 * SECURITY POSTURE, stated up front because it is the whole reason this is safe
 * to ship in a credential app:
 *
 * - **Nothing here ever emits a password.** Reuse and weakness are reported by
 *   the *sites* affected and a count, never by the shared secret itself, and the
 *   data classes below deliberately have no field that could carry one. Callers
 *   render the report; they never get the plaintext back out of it.
 * - **The breach check is k-anonymous.** It follows Have I Been Pwned's range
 *   model (https://haveibeenpwned.com/API/v3#PwnedPasswords): the password is
 *   SHA-1 hashed locally, and only the **first five hex characters** of that
 *   hash ever leave the machine. The service returns every suffix under that
 *   prefix and the match is made locally, so the remote never learns which
 *   password - or even which full hash - was queried. SHA-1 is used because the
 *   range API is defined over it; it is not used as a security primitive here.
 * - **The network call is injected, not baked in.** [analyze] takes a
 *   `fetchRange` function, so this object has no HTTP dependency, is trivially
 *   unit-tested offline, and lets the caller supply the app's own configured,
 *   TLS-pinned HTTP client rather than this layer opening sockets of its own.
 *
 * The reuse and strength halves are pure and run with no network at all, so a
 * caller can show them instantly and fold in breach results as they arrive.
 */
object VaultPasswordHealth {
    /** How a single password rates on the local, network-free strength heuristic. */
    enum class Strength { WEAK, FAIR, STRONG }

    /**
     * A set of secrets that share one password, named by their sites. The shared
     * secret itself is intentionally absent.
     */
    data class ReuseGroup(
        val secretIds: List<String>,
        val sites: List<String>,
    ) {
        val count: Int get() = secretIds.size
    }

    /** One secret whose password is weak, with the machine-readable reasons. */
    data class WeakEntry(
        val secretId: String,
        val site: String,
        val strength: Strength,
        val reasons: List<String>,
    )

    /** One secret whose password appears in a known breach corpus, with its exposure count. */
    data class BreachedEntry(
        val secretId: String,
        val site: String,
        val breachCount: Long,
    )

    /** The full report. Every list is ordered most-affected first so a UI can render it directly. */
    data class Report(
        val reused: List<ReuseGroup>,
        val weak: List<WeakEntry>,
        val breached: List<BreachedEntry>,
    ) {
        val hasFindings: Boolean get() = reused.isNotEmpty() || weak.isNotEmpty() || breached.isNotEmpty()
    }

    // A small, lower-cased set of the passwords that top every breach corpus.
    // Deliberately tiny: the breach check is the real defence against common
    // passwords, and this only exists so the offline strength pass can call the
    // most notorious ones weak without a network round trip.
    private val NOTORIOUS_PASSWORDS: Set<String> =
        setOf(
            "password",
            "123456",
            "123456789",
            "12345678",
            "12345",
            "1234567",
            "qwerty",
            "abc123",
            "password1",
            "111111",
            "letmein",
            "welcome",
            "admin",
            "iloveyou",
            "monkey",
            "dragon",
            "000000",
            "qwerty123",
        )

    /**
     * Everything that needs no network: which passwords are reused, and which are weak.
     *
     * A secret with a blank password is skipped rather than reported - an empty
     * credential is a data question, not a strength one, and grouping the blanks
     * together as "reused" would be noise.
     */
    fun analyzeLocal(secrets: List<SecretEntry>): Pair<List<ReuseGroup>, List<WeakEntry>> {
        val withPassword = secrets.filter { it.password.isNotEmpty() }

        val reused =
            withPassword
                .groupBy { it.password }
                .values
                .filter { it.size > 1 }
                .map { group ->
                    ReuseGroup(
                        secretIds = group.map { it.id },
                        sites = group.map { it.website },
                    )
                }.sortedByDescending { it.count }

        val weak =
            withPassword
                .mapNotNull { secret ->
                    val (strength, reasons) = rate(secret.password)
                    if (strength == Strength.STRONG) {
                        null
                    } else {
                        WeakEntry(secret.id, secret.website, strength, reasons)
                    }
                }
                // WEAK before FAIR, so the worst offenders are first.
                .sortedBy { it.strength }

        return reused to weak
    }

    /**
     * The full report, including the breach check.
     *
     * [fetchRange] receives an upper-cased five-hex-character prefix and must
     * return the HIBP range body for it (`SUFFIX:COUNT` lines) or null if the
     * lookup could not be made; a null simply omits breach data for the affected
     * passwords rather than failing the whole report, so reuse and strength still
     * render when the network is down. One request is made per DISTINCT password,
     * never per secret, so a reused password is checked once.
     */
    suspend fun analyze(
        secrets: List<SecretEntry>,
        fetchRange: suspend (prefix: String) -> String?,
    ): Report {
        val (reused, weak) = analyzeLocal(secrets)

        // Distinct non-blank passwords, each mapped to the secrets that use it.
        val byPassword = secrets.filter { it.password.isNotEmpty() }.groupBy { it.password }

        val breached = mutableListOf<BreachedEntry>()
        // Cache range bodies by prefix so two passwords sharing a prefix cost one call.
        val rangeCache = HashMap<String, String?>()

        for ((password, group) in byPassword) {
            val sha1 = sha1Hex(password)
            val prefix = sha1.substring(0, 5)
            val suffix = sha1.substring(5)
            val body = rangeCache.getOrPut(prefix) { fetchRange(prefix) } ?: continue
            val count = breachCountFor(suffix, body)
            if (count > 0) {
                for (secret in group) {
                    breached += BreachedEntry(secret.id, secret.website, count)
                }
            }
        }

        return Report(
            reused = reused,
            weak = weak,
            breached = breached.sortedByDescending { it.breachCount },
        )
    }

    /**
     * Parse a HIBP range body and return the breach count for [suffix], or 0.
     *
     * The body is CRLF- or LF-separated `HASHSUFFIX:COUNT` lines, upper-cased by
     * the API. Matching is case-insensitive and tolerant of surrounding
     * whitespace; a malformed count contributes 0 rather than throwing, so one
     * bad line cannot sink the check. Public so it can be pinned directly.
     */
    fun breachCountFor(
        suffix: String,
        rangeBody: String,
    ): Long {
        val target = suffix.uppercase(Locale.ROOT)
        for (rawLine in rangeBody.lineSequence()) {
            val line = rawLine.trim()
            if (line.isEmpty()) continue
            val sep = line.indexOf(':')
            if (sep <= 0) continue
            val hashSuffix = line.substring(0, sep).trim().uppercase(Locale.ROOT)
            if (hashSuffix != target) continue
            return line.substring(sep + 1).trim().toLongOrNull() ?: 0L
        }
        return 0L
    }

    /**
     * SHA-1 of the UTF-8 bytes of [value], as upper-case hex.
     *
     * SHA-1 is mandated by the HIBP range protocol; this is not a security use of
     * SHA-1. Upper-case because that is the casing the range API returns, which
     * keeps [breachCountFor]'s comparison a plain equality.
     */
    fun sha1Hex(value: String): String {
        val digest = MessageDigest.getInstance("SHA-1").digest(value.toByteArray(Charsets.UTF_8))
        val sb = StringBuilder(digest.size * 2)
        for (b in digest) {
            val v = b.toInt() and 0xff
            sb.append(HEX[v ushr 4])
            sb.append(HEX[v and 0x0f])
        }
        return sb.toString()
    }

    private val HEX = "0123456789ABCDEF".toCharArray()

    /**
     * The offline strength heuristic for one password.
     *
     * Deliberately simple and explainable rather than an entropy estimator: the
     * breach check is what catches a "strong-looking" password that is actually
     * common, so this only has to catch the passwords that are weak by shape.
     * Returned reasons are UI-facing labels, so keep them human.
     */
    fun rate(password: String): Pair<Strength, List<String>> {
        if (password.lowercase(Locale.ROOT) in NOTORIOUS_PASSWORDS) {
            return Strength.WEAK to listOf("This is one of the most common passwords in breaches")
        }

        val reasons = mutableListOf<String>()
        val length = password.length
        val hasLower = password.any { it in 'a'..'z' }
        val hasUpper = password.any { it in 'A'..'Z' }
        val hasDigit = password.any { it.isDigit() }
        val hasSymbol = password.any { !it.isLetterOrDigit() }
        val classes = listOf(hasLower, hasUpper, hasDigit, hasSymbol).count { it }

        if (length < 8) reasons += "Shorter than 8 characters"
        if (classes < 2) {
            reasons += "Uses only one kind of character"
        } else if (classes < 3 && length < 12) {
            reasons += "Mixes only two kinds of character"
        }

        val strength =
            when {
                length < 8 || classes < 2 -> Strength.WEAK
                length >= 12 && classes >= 3 -> Strength.STRONG
                length >= 16 -> Strength.STRONG
                else -> Strength.FAIR
            }

        return strength to reasons
    }
}
