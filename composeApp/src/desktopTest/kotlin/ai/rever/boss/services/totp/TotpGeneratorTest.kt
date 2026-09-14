package ai.rever.boss.services.totp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Pins [TotpGenerator] against the published RFC 6238 Appendix B test vectors.
 *
 * The seed there is the ASCII string "12345678901234567890"; for SHA-1 that is 20
 * bytes, which Base32-encodes to "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ". Matching the
 * RFC's 8-digit codes at its exact timestamps is what proves the HOTP dynamic
 * truncation and the counter derivation are correct - the two things that are easy
 * to get subtly wrong and impossible to eyeball.
 */
class TotpGeneratorTest {
    private val sha1Base32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
    private val p8 = TotpGenerator.Params(TotpGenerator.Algorithm.SHA1, digits = 8, periodSeconds = 30)

    @Test
    fun `base32Decode round-trips the RFC seed to ASCII digits`() {
        // "GEZDGNBVGY3TQOJQ" is the Base32 of ASCII "1234567890".
        val bytes = TotpGenerator.base32Decode("GEZDGNBVGY3TQOJQ")
        assertEquals("1234567890", String(bytes, Charsets.US_ASCII))
    }

    @Test
    fun `matches RFC 6238 Appendix B SHA-1 vectors`() {
        assertEquals("94287082", TotpGenerator.code(sha1Base32, 59L, p8))
        assertEquals("07081804", TotpGenerator.code(sha1Base32, 1111111109L, p8))
        assertEquals("14050471", TotpGenerator.code(sha1Base32, 1111111111L, p8))
        assertEquals("89005924", TotpGenerator.code(sha1Base32, 1234567890L, p8))
        assertEquals("69279037", TotpGenerator.code(sha1Base32, 2000000000L, p8))
    }

    @Test
    fun `default params produce a 6-digit code`() {
        val code = TotpGenerator.code(sha1Base32, 59L)
        assertEquals(6, code.length)
        assertTrue(code.all { it.isDigit() })
        // 6-digit truncation of the same instant the RFC gives as 94287082.
        assertEquals("287082", code)
    }

    @Test
    fun `base32 decoding is case-insensitive and ignores spaces and padding`() {
        assertEquals(
            TotpGenerator.code(sha1Base32, 59L, p8),
            TotpGenerator.code("gezd gnbv gy3t qojq gezd gnbv gy3t qojq===", 59L, p8),
        )
    }

    @Test
    fun `an invalid seed fails loudly rather than emitting a code`() {
        assertFailsWith<IllegalArgumentException> { TotpGenerator.code("not-base32!!!", 59L) }
        assertFailsWith<IllegalArgumentException> { TotpGenerator.code("GEZDGNBVGY3TQOJQ", 59L, p8.copy(digits = 0)) }
    }
}
