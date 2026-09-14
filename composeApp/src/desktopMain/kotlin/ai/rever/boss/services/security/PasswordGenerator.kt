package ai.rever.boss.services.security

import kotlin.math.ln
import kotlin.random.Random
import kotlin.random.asKotlinRandom

/**
 * Generates strong passwords and diceware passphrases - the "fix it" half a
 * password manager needs beside a health report: flag a weak, reused or breached
 * password, then offer a strong replacement.
 *
 * Two design choices make this safe and testable:
 *
 * - **The randomness is injected.** Production callers get a
 *   [java.security.SecureRandom]-backed [Random] (the default), which is the only
 *   correct source for a secret; tests pass a seeded [Random] so the exact output
 *   can be pinned. A generator that seeded itself could not be verified without
 *   mocking, and one that reached for [kotlin.random.Random.Default] would be
 *   predictable - the bug this exists to avoid.
 * - **It never logs and never persists.** The returned string is the secret; the
 *   caller writes it to the encrypted vault and drops the reference.
 *
 * The diceware side takes the wordlist as an argument rather than bundling one:
 * the correctness-critical part is the uniform selection and the entropy claim,
 * both of which are pure, and the choice of wordlist (EFF, language) belongs to
 * the surface that offers the feature.
 */
object PasswordGenerator {
    const val LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
    const val UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    const val DIGITS = "0123456789"

    /**
     * A conservative symbol set: punctuation that every site accepts, with the
     * shell-hostile quote, backslash and space left out so a generated password
     * can be pasted into a terminal or a config file without escaping surprises.
     */
    const val SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"

    /**
     * Characters that are hard to tell apart in common fonts, dropped when
     * [Options.excludeAmbiguous] is set - for a password a human will read off a
     * screen and retype. Removing them costs a little entropy per character,
     * which [entropyBits] reflects because it measures the pool actually used.
     */
    const val AMBIGUOUS = "Il1O0o|"

    private const val LOG2 = 0.6931471805599453

    /** What a generated password is built from. */
    data class Options(
        val length: Int = 20,
        val lowercase: Boolean = true,
        val uppercase: Boolean = true,
        val digits: Boolean = true,
        val symbols: Boolean = true,
        val excludeAmbiguous: Boolean = false,
    ) {
        /** The character classes this selects, each already ambiguity-filtered. */
        internal fun pools(): List<String> {
            val raw =
                buildList {
                    if (lowercase) add(LOWERCASE)
                    if (uppercase) add(UPPERCASE)
                    if (digits) add(DIGITS)
                    if (symbols) add(SYMBOLS)
                }
            val filtered =
                if (excludeAmbiguous) {
                    raw.map { pool -> pool.filter { it !in AMBIGUOUS } }
                } else {
                    raw
                }
            return filtered.filter { it.isNotEmpty() }
        }
    }

    /**
     * A random password matching [options].
     *
     * Guarantees at least one character from every selected class, then fills the
     * rest from the union of the classes and shuffles - so the guaranteed
     * characters are not stuck at the front, which would leak the class order and
     * weaken the result against a cracker that knows the policy.
     *
     * @throws IllegalArgumentException if no class is selected, or the length is
     *   too short to place one character from each selected class.
     */
    fun generate(
        options: Options = Options(),
        random: Random = secureRandom(),
    ): String {
        val pools = options.pools()
        require(pools.isNotEmpty()) { "at least one character class must be selected" }
        require(options.length >= pools.size) {
            "length ${options.length} is too short for ${pools.size} required character classes"
        }

        val all = pools.joinToString("")
        val chars = ArrayList<Char>(options.length)
        // One from each class first, so the policy is always satisfied.
        pools.forEach { pool -> chars.add(pool[random.nextInt(pool.length)]) }
        // Then fill from the union.
        repeat(options.length - pools.size) { chars.add(all[random.nextInt(all.length)]) }

        chars.shuffle(random)
        return chars.joinToString("")
    }

    /** How a diceware passphrase is shaped. */
    data class PassphraseOptions(
        val wordCount: Int = 4,
        val separator: String = "-",
        val capitalize: Boolean = false,
        val includeNumber: Boolean = false,
    )

    /**
     * A diceware passphrase: [PassphraseOptions.wordCount] words drawn uniformly
     * and independently from [wordlist], joined by [PassphraseOptions.separator].
     *
     * [PassphraseOptions.capitalize] title-cases each word and
     * [PassphraseOptions.includeNumber] appends a single digit to one randomly
     * chosen word - both are readability/policy sugar and neither is counted
     * toward [passphraseEntropyBits], which measures only the word selection so
     * the number it reports is never optimistic.
     *
     * @throws IllegalArgumentException if the wordlist is empty, has duplicates,
     *   or the word count is not positive. Duplicates are rejected because they
     *   would quietly make the real entropy lower than `log2(size) * words` claims.
     */
    fun passphrase(
        wordlist: List<String>,
        options: PassphraseOptions = PassphraseOptions(),
        random: Random = secureRandom(),
    ): String {
        require(options.wordCount > 0) { "wordCount must be positive" }
        require(wordlist.isNotEmpty()) { "wordlist must not be empty" }
        require(wordlist.size == wordlist.toHashSet().size) { "wordlist must not contain duplicates" }

        val words =
            MutableList(options.wordCount) {
                val word = wordlist[random.nextInt(wordlist.size)]
                if (options.capitalize) word.replaceFirstChar { it.uppercaseChar() } else word
            }
        if (options.includeNumber) {
            val at = random.nextInt(words.size)
            words[at] = words[at] + random.nextInt(10)
        }
        return words.joinToString(options.separator)
    }

    /**
     * Shannon entropy in bits of a password drawn uniformly from a pool of
     * [poolSize] distinct characters at [length] characters: `length * log2(pool)`.
     *
     * This is the entropy of the *generator*, valid only for a uniformly random
     * string; it is not a strength estimate for a human-chosen password.
     */
    fun entropyBits(
        length: Int,
        poolSize: Int,
    ): Double {
        if (length <= 0 || poolSize <= 1) return 0.0
        return length * (ln(poolSize.toDouble()) / LOG2)
    }

    /** Entropy in bits of a [wordCount]-word passphrase over a [wordlistSize]-word list. */
    fun passphraseEntropyBits(
        wordCount: Int,
        wordlistSize: Int,
    ): Double = entropyBits(wordCount, wordlistSize)

    /** The entropy [generate] would produce for [options]: its length over its filtered pool. */
    fun entropyBits(options: Options): Double = entropyBits(options.length, options.pools().sumOf { it.length })

    /** A [Random] backed by [java.security.SecureRandom] - the only correct source for a secret. */
    private fun secureRandom(): Random = java.security.SecureRandom().asKotlinRandom()
}
