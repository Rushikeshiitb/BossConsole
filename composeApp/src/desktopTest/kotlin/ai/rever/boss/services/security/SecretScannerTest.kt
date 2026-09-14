package ai.rever.boss.services.security

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Pins [SecretScanner]: the credential shapes it detects, the false positives it does not, and its masking. */
class SecretScannerTest {
    private val awsKey = "AKIAIOSFODNN7EXAMPLE"
    private val githubToken = "ghp_" + "a".repeat(36)
    private val googleKey = "AIza" + "B".repeat(35)
    private val slackToken = "xoxb-012345678901234"
    private val jwt = "eyJ" + "a".repeat(10) + "." + "b".repeat(8) + "." + "c".repeat(8)
    private val privateKeyHeader = "-----BEGIN RSA PRIVATE KEY-----"

    @Test
    fun `detects each well-known credential shape`() {
        assertEquals(SecretScanner.Rule.AWS_ACCESS_KEY, SecretScanner.scan("key = $awsKey").single().rule)
        assertEquals(SecretScanner.Rule.GITHUB_TOKEN, SecretScanner.scan("t=$githubToken").single().rule)
        assertEquals(SecretScanner.Rule.GOOGLE_API_KEY, SecretScanner.scan("g=$googleKey").single().rule)
        assertEquals(SecretScanner.Rule.SLACK_TOKEN, SecretScanner.scan("s=$slackToken").single().rule)
        assertEquals(SecretScanner.Rule.PRIVATE_KEY, SecretScanner.scan(privateKeyHeader).single().rule)
        assertEquals(SecretScanner.Rule.JWT, SecretScanner.scan("auth: $jwt").single().rule)
    }

    @Test
    fun `detects a hardcoded credential assignment`() {
        val findings = SecretScanner.scan("val password = \"S3cr3tP@ssw0rd\"")
        assertEquals(1, findings.size)
        assertEquals(SecretScanner.Rule.GENERIC_ASSIGNMENT, findings.single().rule)
    }

    @Test
    fun `does not flag placeholders and templated values`() {
        assertTrue(SecretScanner.scan("api_key = \"\${SECRET}\"").isEmpty(), "template ref")
        assertTrue(SecretScanner.scan("api_key = \"your_api_key_here\"").isEmpty(), "your_ placeholder")
        assertTrue(SecretScanner.scan("token = \"example-value-123\"").isEmpty(), "example placeholder")
    }

    @Test
    fun `clean code has no findings`() {
        assertFalse(SecretScanner.containsSecret("fun add(a: Int, b: Int) = a + b\nval name = \"widget\""))
    }

    @Test
    fun `reports the correct 1-based line and column`() {
        val content = "line one\nline two\nval k = $awsKey\n"
        val finding = SecretScanner.scan(content).single()
        assertEquals(3, finding.line)
        assertEquals(9, finding.column, "the key starts after 'val k = '")
    }

    @Test
    fun `the preview never contains the raw secret`() {
        val content = "aws=$awsKey; gh=$githubToken; jwt=$jwt"
        val findings = SecretScanner.scan(content)
        assertEquals(3, findings.size)
        for (secret in listOf(awsKey, githubToken, jwt)) {
            assertTrue(findings.none { it.preview.contains(secret) }, "preview leaked $secret")
        }
    }

    @Test
    fun `redact strips secrets and preserves surrounding text`() {
        val redacted = SecretScanner.redact("val k = \"$awsKey\" // deploy key")
        assertEquals("val k = \"[REDACTED]\" // deploy key", redacted)
        assertFalse(redacted.contains(awsKey))
    }

    @Test
    fun `finds multiple distinct secrets`() {
        val content = "a=$awsKey\nb=$slackToken"
        val findings = SecretScanner.scan(content)
        assertEquals(2, findings.size)
        assertEquals(listOf(1, 2), findings.map { it.line })
    }
}
