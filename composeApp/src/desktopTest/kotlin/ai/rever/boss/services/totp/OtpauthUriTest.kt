package ai.rever.boss.services.totp

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Pins [OtpauthUri] against the Key Uri Format: the label of `issuer:account`,
 * percent-decoding, the `issuer` parameter overriding the label prefix, HOTP's
 * required counter, and a build/parse round trip. A mis-parsed period or a dropped
 * issuer is exactly what a user would only discover when a code stops matching.
 */
class OtpauthUriTest {
    private val secret = "JBSWY3DPEHPK3PXP"

    @Test
    fun `parses a full TOTP URI`() {
        val c =
            OtpauthUri.parse(
                "otpauth://totp/ACME%20Co:john@example.com" +
                    "?secret=$secret&issuer=ACME%20Co&algorithm=SHA256&digits=8&period=60",
            )
        assertEquals(OtpauthUri.Type.TOTP, c.type)
        assertEquals(secret, c.secret)
        assertEquals("ACME Co", c.issuer)
        assertEquals("john@example.com", c.accountName)
        assertEquals(OtpauthUri.Algorithm.SHA256, c.algorithm)
        assertEquals(8, c.digits)
        assertEquals(60, c.period)
    }

    @Test
    fun `applies RFC defaults when parameters are omitted`() {
        val c = OtpauthUri.parse("otpauth://totp/Example:alice@google.com?secret=$secret")
        assertEquals(OtpauthUri.Algorithm.SHA1, c.algorithm)
        assertEquals(OtpauthUri.DEFAULT_DIGITS, c.digits)
        assertEquals(OtpauthUri.DEFAULT_PERIOD, c.period)
        assertEquals("Example", c.issuer)
        assertEquals("alice@google.com", c.accountName)
    }

    @Test
    fun `the issuer parameter overrides the label prefix`() {
        val c = OtpauthUri.parse("otpauth://totp/Label%20Issuer:acct?secret=$secret&issuer=Param%20Issuer")
        assertEquals("Param Issuer", c.issuer)
        assertEquals("acct", c.accountName)
    }

    @Test
    fun `a label with no issuer prefix leaves the issuer null`() {
        val c = OtpauthUri.parse("otpauth://totp/justtheaccount?secret=$secret")
        assertNull(c.issuer)
        assertEquals("justtheaccount", c.accountName)
    }

    @Test
    fun `the secret is canonicalised - uppercased, spaces and padding removed`() {
        val c = OtpauthUri.parse("otpauth://totp/x?secret=jbswy3dp%20ehpk3pxp===")
        assertEquals(secret, c.secret)
    }

    @Test
    fun `HOTP carries its counter and requires one`() {
        val c = OtpauthUri.parse("otpauth://hotp/Bank:me?secret=$secret&counter=42")
        assertEquals(OtpauthUri.Type.HOTP, c.type)
        assertEquals(42L, c.counter)
        assertFailsWith<IllegalArgumentException> { OtpauthUri.parse("otpauth://hotp/Bank:me?secret=$secret") }
    }

    @Test
    fun `rejects a bad scheme, type, secret and out-of-range values`() {
        assertFailsWith<IllegalArgumentException> { OtpauthUri.parse("https://totp/x?secret=$secret") }
        assertFailsWith<IllegalArgumentException> { OtpauthUri.parse("otpauth://xotp/x?secret=$secret") }
        assertFailsWith<IllegalArgumentException> { OtpauthUri.parse("otpauth://totp/x?secret=not-base32!") }
        assertFailsWith<IllegalArgumentException> { OtpauthUri.parse("otpauth://totp/x") }
        assertFailsWith<IllegalArgumentException> { OtpauthUri.parse("otpauth://totp/x?secret=$secret&digits=0") }
        assertFailsWith<IllegalArgumentException> { OtpauthUri.parse("otpauth://totp/x?secret=$secret&period=0") }
    }

    @Test
    fun `an error message never contains the secret`() {
        val e =
            assertFailsWith<IllegalArgumentException> {
                OtpauthUri.parse("otpauth://totp/x?secret=$secret&digits=abc")
            }
        assertTrue(!(e.message ?: "").contains(secret), "message leaked the secret: ${e.message}")
    }

    @Test
    fun `parseOrNull returns null instead of throwing`() {
        assertNull(OtpauthUri.parseOrNull("not a uri"))
        assertTrue(OtpauthUri.parseOrNull("otpauth://totp/x?secret=$secret") != null)
    }

    @Test
    fun `build round-trips through parse for TOTP and HOTP`() {
        val totp =
            OtpauthUri.Credential(
                type = OtpauthUri.Type.TOTP,
                secret = secret,
                issuer = "ACME Co",
                accountName = "john@example.com",
                algorithm = OtpauthUri.Algorithm.SHA256,
                digits = 8,
                period = 60,
            )
        assertEquals(totp, OtpauthUri.parse(OtpauthUri.build(totp)))

        val hotp =
            OtpauthUri.Credential(
                type = OtpauthUri.Type.HOTP,
                secret = secret,
                issuer = "Issuer",
                accountName = "account",
                counter = 7L,
            )
        assertEquals(hotp, OtpauthUri.parse(OtpauthUri.build(hotp)))
    }
}
