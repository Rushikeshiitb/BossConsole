package ai.rever.boss.services.security

import kotlin.math.abs
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Pins [PasswordGenerator]. The randomness is injected, so every property here is
 * checked against a seeded [Random] with no mocking - the whole point of taking
 * the source as a parameter.
 */
class PasswordGeneratorTest {
    @Test
    fun `generate honours length and every selected class`() {
        val pw = PasswordGenerator.generate(PasswordGenerator.Options(length = 32), Random(1))
        assertEquals(32, pw.length)
        assertTrue(pw.any { it in PasswordGenerator.LOWERCASE }, "has a lowercase")
        assertTrue(pw.any { it in PasswordGenerator.UPPERCASE }, "has an uppercase")
        assertTrue(pw.any { it in PasswordGenerator.DIGITS }, "has a digit")
        assertTrue(pw.any { it in PasswordGenerator.SYMBOLS }, "has a symbol")
    }

    @Test
    fun `excludeAmbiguous emits no ambiguous characters`() {
        val pw =
            PasswordGenerator.generate(
                PasswordGenerator.Options(length = 200, excludeAmbiguous = true),
                Random(7),
            )
        assertTrue(pw.none { it in PasswordGenerator.AMBIGUOUS }, "no ambiguous characters: $pw")
    }

    @Test
    fun `a single selected class yields only that class`() {
        val pw =
            PasswordGenerator.generate(
                PasswordGenerator.Options(length = 16, lowercase = false, uppercase = false, symbols = false),
                Random(3),
            )
        assertEquals(16, pw.length)
        assertTrue(pw.all { it in PasswordGenerator.DIGITS }, "digits only: $pw")
    }

    @Test
    fun `generation is deterministic for a given seed`() {
        val a = PasswordGenerator.generate(PasswordGenerator.Options(length = 24), Random(42))
        val b = PasswordGenerator.generate(PasswordGenerator.Options(length = 24), Random(42))
        assertEquals(a, b)
    }

    @Test
    fun `generate rejects no classes and a length below the class count`() {
        assertFailsWith<IllegalArgumentException> {
            PasswordGenerator.generate(
                PasswordGenerator.Options(lowercase = false, uppercase = false, digits = false, symbols = false),
            )
        }
        // Four classes selected but length 3 cannot place one of each.
        assertFailsWith<IllegalArgumentException> {
            PasswordGenerator.generate(PasswordGenerator.Options(length = 3))
        }
    }

    @Test
    fun `passphrase draws the requested number of words and joins them`() {
        val list = listOf("alpha", "bravo", "charlie", "delta", "echo", "foxtrot")
        val phrase =
            PasswordGenerator.passphrase(
                list,
                PasswordGenerator.PassphraseOptions(wordCount = 4, separator = "."),
                Random(9),
            )
        val parts = phrase.split(".")
        assertEquals(4, parts.size)
        assertTrue(parts.all { it in list }, "every part is a wordlist entry: $phrase")
    }

    @Test
    fun `passphrase capitalisation and number are applied`() {
        val list = listOf("alpha", "bravo", "charlie", "delta")
        val phrase =
            PasswordGenerator.passphrase(
                wordlist = list,
                options =
                    PasswordGenerator.PassphraseOptions(
                        wordCount = 3,
                        separator = "-",
                        capitalize = true,
                        includeNumber = true,
                    ),
                random = Random(5),
            )
        val parts = phrase.split("-")
        assertEquals(3, parts.size)
        // Each word starts capitalised; exactly one carries a trailing digit.
        assertTrue(parts.all { it.first().isUpperCase() }, "each word capitalised: $phrase")
        assertEquals(1, parts.count { it.last().isDigit() }, "exactly one trailing digit: $phrase")
    }

    @Test
    fun `passphrase rejects an empty or duplicated wordlist and a non-positive count`() {
        val opts3 = PasswordGenerator.PassphraseOptions(wordCount = 3)
        assertFailsWith<IllegalArgumentException> { PasswordGenerator.passphrase(emptyList(), opts3) }
        assertFailsWith<IllegalArgumentException> { PasswordGenerator.passphrase(listOf("a", "a", "b"), opts3) }
        assertFailsWith<IllegalArgumentException> {
            PasswordGenerator.passphrase(listOf("a", "b"), PasswordGenerator.PassphraseOptions(wordCount = 0))
        }
    }

    @Test
    fun `entropy is length times log2 of the pool`() {
        // 20 chars over a 64-char pool is exactly 120 bits (log2(64) = 6).
        assertTrue(abs(PasswordGenerator.entropyBits(20, 64) - 120.0) < 1e-9)
        // A diceware list of 7776 words gives ~12.925 bits per word.
        assertTrue(abs(PasswordGenerator.passphraseEntropyBits(1, 7776) - 12.9248125) < 1e-4)
        // Degenerate pools carry no entropy.
        assertEquals(0.0, PasswordGenerator.entropyBits(20, 1))
        assertEquals(0.0, PasswordGenerator.entropyBits(0, 64))
    }
}
