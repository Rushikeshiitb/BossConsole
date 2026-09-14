package ai.rever.boss.services.security

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins [HomographGuard]. Lookalike characters are written as `\u` escapes so the
 * intent is unambiguous in source and the test cannot be silently "fixed" by an
 * editor normalising the glyph.
 */
class HomographGuardTest {
    @Test
    fun `a plain ASCII domain is safe`() {
        val v = HomographGuard.analyze("paypal.com")
        assertFalse(v.suspicious)
        assertTrue(v.reasons.isEmpty())
    }

    @Test
    fun `a Latin IDN with diacritics is safe`() {
        // bucher.de with an u-umlaut: still one script (Latin).
        assertFalse(HomographGuard.isSuspicious("b\u00FCcher.de"))
    }

    @Test
    fun `a mixed-script label is flagged`() {
        // "\u0430pple.com": Cyrillic а (U+0430) followed by Latin pple.
        val v = HomographGuard.analyze("\u0430pple.com")
        assertTrue(v.suspicious)
        assertTrue(HomographGuard.Reason.MIXED_SCRIPT in v.reasons)
    }

    @Test
    fun `a whole-script Latin lookalike is flagged`() {
        // "аррӏе": every letter Cyrillic and a Latin lookalike (а р р ӏ е).
        val v = HomographGuard.analyze("\u0430\u0440\u0440\u04CF\u0435.com")
        assertTrue(v.suspicious)
        assertTrue(HomographGuard.Reason.WHOLE_SCRIPT_CONFUSABLE in v.reasons)
    }

    @Test
    fun `a legitimate non-Latin IDN is not flagged`() {
        // "яндекс": Cyrillic, but я н д к are not Latin lookalikes, so not a spoof.
        val v = HomographGuard.analyze("\u044F\u043D\u0434\u0435\u043A\u0441.com")
        assertFalse(v.suspicious, "reasons: ${v.reasons}")
    }

    @Test
    fun `a raw punycode label is flagged as advisory`() {
        val v = HomographGuard.analyze("xn--80ak6aa92e.com")
        assertTrue(v.suspicious)
        assertEquals(listOf(HomographGuard.Reason.PUNYCODE), v.reasons)
    }

    @Test
    fun `digits and hyphens do not count as a second script`() {
        assertFalse(HomographGuard.isSuspicious("api-v2.example.com"))
    }
}
