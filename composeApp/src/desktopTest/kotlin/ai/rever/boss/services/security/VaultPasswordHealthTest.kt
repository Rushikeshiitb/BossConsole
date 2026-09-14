package ai.rever.boss.services.security

import ai.rever.boss.services.supabase.models.SecretEntry
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins [VaultPasswordHealth]: the SHA-1 vector the HIBP range protocol depends on,
 * the k-anonymous breach match, reuse grouping, and the offline strength heuristic.
 *
 * The breach check is driven by an injected `fetchRange` so the whole thing runs
 * offline and deterministically - no network, and the test asserts that only the
 * five-character prefix is ever passed out.
 */
class VaultPasswordHealthTest {
    private fun secret(
        id: String,
        site: String,
        password: String,
    ): SecretEntry =
        SecretEntry(
            id = id,
            website = site,
            username = "user@$site",
            password = password,
            createdAt = "2026-01-01T00:00:00Z",
            updatedAt = "2026-01-01T00:00:00Z",
        )

    // SHA-1("password") = 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8 (a fixed, published value).
    private val passwordSha1 = "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"

    @Test
    fun `sha1Hex matches the known vector and is upper-case hex`() {
        assertEquals(passwordSha1, VaultPasswordHealth.sha1Hex("password"))
    }

    @Test
    fun `breachCountFor matches the suffix case-insensitively and tolerates junk lines`() {
        val suffix = passwordSha1.substring(5) // 1E4C9B93F3F0682250B6CF8331B7EE68FD8
        val body =
            buildString {
                append("003D68EB55068C33ACE09247EE4C639306B:3\r\n")
                append("garbage-with-no-colon\r\n")
                append(":123\r\n") // empty suffix, must be ignored
                // Real match, given lower-case to prove case-insensitivity:
                append(suffix.lowercase()).append(":37359195\r\n")
                append("00000000000000000000000000000000000:notanumber\r\n")
            }
        assertEquals(37359195L, VaultPasswordHealth.breachCountFor(suffix, body))
        assertEquals(0L, VaultPasswordHealth.breachCountFor("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", body))
    }

    @Test
    fun `analyzeLocal groups reused passwords by site and omits the password`() {
        val (reused, _) =
            VaultPasswordHealth.analyzeLocal(
                listOf(
                    secret("1", "a.com", "SharedP@ssw0rd!"),
                    secret("2", "b.com", "SharedP@ssw0rd!"),
                    secret("3", "c.com", "unique-Str0ng-one!!"),
                ),
            )
        assertEquals(1, reused.size)
        assertEquals(2, reused[0].count)
        assertEquals(setOf("1", "2"), reused[0].secretIds.toSet())
        assertEquals(setOf("a.com", "b.com"), reused[0].sites.toSet())
    }

    @Test
    fun `rate flags short and single-class passwords weak and a long mixed one strong`() {
        assertEquals(VaultPasswordHealth.Strength.WEAK, VaultPasswordHealth.rate("123456").first)
        assertEquals(VaultPasswordHealth.Strength.WEAK, VaultPasswordHealth.rate("abc").first)
        assertEquals(VaultPasswordHealth.Strength.WEAK, VaultPasswordHealth.rate("alllowercase").first)
        assertEquals(VaultPasswordHealth.Strength.STRONG, VaultPasswordHealth.rate("Tr0ub4dour&3xplr").first)
    }

    @Test
    fun `analyze flags a breached password, checks each distinct password once, and leaks only the prefix`() =
        runBlocking {
            val seenPrefixes = mutableListOf<String>()
            val suffix = passwordSha1.substring(5)
            val fetch: suspend (String) -> String? = { prefix ->
                seenPrefixes += prefix
                // Only answer for the "password" prefix; everything else is unbreached.
                if (prefix == passwordSha1.substring(0, 5)) "$suffix:37359195" else ""
            }

            val report =
                VaultPasswordHealth.analyze(
                    listOf(
                        secret("1", "a.com", "password"),
                        secret("2", "b.com", "password"), // same password: one fetch, two breached rows
                        secret("3", "c.com", "an-unbreached-Str0ng-secret!"),
                    ),
                    fetch,
                )

            // Two secrets share "password", so both are reported breached...
            assertEquals(setOf("1", "2"), report.breached.map { it.secretId }.toSet())
            assertTrue(report.breached.all { it.breachCount == 37359195L })
            assertFalse(report.breached.any { it.secretId == "3" })

            // ...but the network was hit once per DISTINCT password (2), not once per secret (3).
            assertEquals(2, seenPrefixes.size)
            // Every value that left the machine was exactly a 5-char prefix - never a full hash.
            assertTrue(seenPrefixes.all { it.length == 5 })
        }
}
