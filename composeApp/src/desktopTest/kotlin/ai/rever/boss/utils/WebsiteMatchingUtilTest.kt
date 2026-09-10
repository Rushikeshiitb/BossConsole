package ai.rever.boss.utils

import ai.rever.boss.services.supabase.models.SecretEntry
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the secret-to-website matching behind the Fluck browser's credential suggestion
 * (`BrowserSecretIntegrationViewModel`). Regression cover for issue #460: the matcher used to
 * over-match so badly that the browser offered the wrong site's saved secrets.
 */
class WebsiteMatchingUtilTest {
    private fun secret(website: String) =
        SecretEntry(
            id = website,
            website = website,
            username = "u",
            password = "p",
            createdAt = "2026-01-01",
            updatedAt = "2026-01-01",
        )

    // --- calculateMatchScore: only genuine matches score above the 0.3 offer threshold ---

    @Test
    fun `an exact registrable-domain match scores 1`() {
        assertEquals(1.0f, WebsiteMatchingUtil.calculateMatchScore("google.com", "google.com").score)
    }

    @Test
    fun `a real subdomain boundary matches, in either direction`() {
        assertEquals(0.9f, WebsiteMatchingUtil.calculateMatchScore("login.google.com", "google.com").score)
        assertEquals(0.9f, WebsiteMatchingUtil.calculateMatchScore("google.com", "login.google.com").score)
    }

    @Test
    fun `a www prefix does not stop an exact match`() {
        assertEquals(1.0f, WebsiteMatchingUtil.calculateMatchScore("www.google.com", "google.com").score)
    }

    @Test
    fun `bug A - a bare substring is not a match`() {
        // snapple.com contains "apple.com"; login-apple.com contains "apple.com". Neither is apple.com.
        assertEquals(0.0f, WebsiteMatchingUtil.calculateMatchScore("apple.com", "snapple.com").score)
        assertEquals(0.0f, WebsiteMatchingUtil.calculateMatchScore("apple.com", "login-apple.com").score)
    }

    @Test
    fun `bug B - a shared public suffix is not a match`() {
        // Every .com domain shares the "com" part; that must not make them match.
        val s = WebsiteMatchingUtil.calculateMatchScore("google.com", "example.com")
        assertEquals(0.0f, s.score)
        assertTrue(s.score <= 0.3f, "must fall below the offer threshold")
    }

    // --- matchSecretsForDomain: the actual offer path the browser uses ---

    @Test
    fun `only secrets for the current site are offered`() {
        val secrets = listOf(secret("apple.com"), secret("google.com"))

        // The right site gets its secret.
        assertEquals(
            listOf("google.com"),
            WebsiteMatchingUtil.matchSecretsForDomain("google.com", secrets).map { it.secret.website },
        )
        // A look-alike (bug A) offers nothing.
        assertTrue(WebsiteMatchingUtil.matchSecretsForDomain("snapple.com", secrets).isEmpty())
        // An unrelated same-TLD site (bug B) offers nothing.
        assertTrue(WebsiteMatchingUtil.matchSecretsForDomain("example.com", secrets).isEmpty())
    }

    // --- getDisplayName: bug C ---

    @Test
    fun `bug C - a digit-initial domain name is not duplicated`() {
        assertEquals("1password", WebsiteMatchingUtil.getDisplayName("1password.com"))
        assertEquals("9gag", WebsiteMatchingUtil.getDisplayName("9gag.com"))
    }

    @Test
    fun `ordinary display names are still title-cased`() {
        assertEquals("Google", WebsiteMatchingUtil.getDisplayName("google.com"))
        assertEquals("Example Site", WebsiteMatchingUtil.getDisplayName("example-site.com"))
    }
}
