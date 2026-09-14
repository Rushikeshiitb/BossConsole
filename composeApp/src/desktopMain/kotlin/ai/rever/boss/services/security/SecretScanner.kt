package ai.rever.boss.services.security

/**
 * Finds hardcoded secrets in source text - the "you committed an API key" guard a
 * developer tool like BOSS can offer over an open project.
 *
 * It matches well-known credential shapes (cloud and vendor keys, private-key
 * headers, JWTs) plus the generic "a secret-named variable assigned a long string
 * literal" pattern, and reports each with a line, a column, and a **masked**
 * preview - never the secret itself, which is the whole point of a tool that
 * surfaces them. [redact] is the same detection used to strip secrets out of text
 * (a log line, a tool result) before it is shown or stored.
 *
 * Pure: [scan] and [redact] are functions of the text alone, so every rule and
 * every false-positive guard is a plain unit test.
 */
object SecretScanner {
    enum class Rule(
        val display: String,
    ) {
        AWS_ACCESS_KEY("AWS access key"),
        GITHUB_TOKEN("GitHub token"),
        GOOGLE_API_KEY("Google API key"),
        SLACK_TOKEN("Slack token"),
        PRIVATE_KEY("Private key"),
        JWT("JSON Web Token"),
        GENERIC_ASSIGNMENT("Hardcoded credential"),
    }

    /** One detection: [line] and [column] are 1-based; [preview] is masked and safe to display or log. */
    data class Finding(
        val rule: Rule,
        val line: Int,
        val column: Int,
        val preview: String,
    )

    private data class Detector(
        val rule: Rule,
        val regex: Regex,
        /** Which capture group is the secret itself; 0 is the whole match. */
        val group: Int = 0,
    )

    private const val REDACTED = "[REDACTED]"
    private const val PREVIEW_PREFIX = 3

    private val DETECTORS =
        listOf(
            Detector(Rule.AWS_ACCESS_KEY, Regex("""(?:AKIA|ASIA)[0-9A-Z]{16}""")),
            Detector(Rule.GITHUB_TOKEN, Regex("""(?:gh[pousr]_|github_pat_)[A-Za-z0-9_]{20,}""")),
            Detector(Rule.GOOGLE_API_KEY, Regex("""AIza[0-9A-Za-z_-]{35}""")),
            Detector(Rule.SLACK_TOKEN, Regex("""xox[baprs]-[A-Za-z0-9-]{10,}""")),
            Detector(Rule.PRIVATE_KEY, Regex("""-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----""")),
            Detector(Rule.JWT, Regex("""eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}""")),
            Detector(
                Rule.GENERIC_ASSIGNMENT,
                Regex(
                    "(?i)(?:api[_-]?key|secret|token|password|passwd|access[_-]?key)" +
                        """\s*[:=]\s*["']([^"'\n]{8,})["']""",
                ),
                group = 1,
            ),
        )

    /** Every secret in [content], most-specific rule winning on overlap, ordered by position. */
    fun scan(content: String): List<Finding> {
        val kept = mutableListOf<RawMatch>()
        var lastEnd = -1
        for (match in rawMatches(content)) {
            if (match.start >= lastEnd) {
                kept.add(match)
                lastEnd = match.end
            }
        }
        return kept
            .map { Finding(it.rule, lineOf(content, it.start), columnOf(content, it.start), mask(it.secret)) }
            .sortedWith(compareBy({ it.line }, { it.column }))
    }

    /** True when [content] holds at least one detectable secret. */
    fun containsSecret(content: String): Boolean = rawMatches(content).isNotEmpty()

    /** [content] with every detected secret replaced by `[REDACTED]`, surrounding text preserved. */
    fun redact(content: String): String {
        val sb = StringBuilder(content.length)
        var cursor = 0
        for (match in rawMatches(content).sortedBy { it.start }) {
            if (match.start < cursor) continue
            sb.append(content, cursor, match.start)
            sb.append(REDACTED)
            cursor = match.end
        }
        sb.append(content, cursor, content.length)
        return sb.toString()
    }

    private data class RawMatch(
        val rule: Rule,
        val start: Int,
        val end: Int,
        val secret: String,
    )

    private fun rawMatches(content: String): List<RawMatch> =
        DETECTORS
            .flatMap { detector -> detector.regex.findAll(content).mapNotNull { rawOf(detector, it) } }
            .sortedWith(compareBy({ it.start }, { it.rule.ordinal }))

    private fun rawOf(
        detector: Detector,
        match: MatchResult,
    ): RawMatch? {
        val group = match.groups[detector.group] ?: return null
        val skip = detector.rule == Rule.GENERIC_ASSIGNMENT && isPlaceholder(group.value)
        return if (skip) null else RawMatch(detector.rule, group.range.first, group.range.last + 1, group.value)
    }

    /** A templated or obviously fake value, so the generic rule does not flag config scaffolding. */
    private fun isPlaceholder(value: String): Boolean {
        val v = value.trim()
        return v.startsWith("$") ||
            v.startsWith("{") ||
            v.startsWith("<") ||
            v.contains("example", ignoreCase = true) ||
            v.contains("changeme", ignoreCase = true) ||
            v.contains("your_", ignoreCase = true) ||
            v.contains("your-", ignoreCase = true) ||
            v.all { it == 'x' || it == 'X' || it == '*' || it == '.' }
    }

    /** Reveal only a short, non-identifying prefix and the length. */
    private fun mask(secret: String): String =
        if (secret.length <= PREVIEW_PREFIX) {
            "*".repeat(secret.length)
        } else {
            secret.take(PREVIEW_PREFIX) + "***(${secret.length} chars)"
        }

    private fun lineOf(
        text: String,
        index: Int,
    ): Int = text.substring(0, index).count { it == '\n' } + 1

    private fun columnOf(
        text: String,
        index: Int,
    ): Int = index - text.lastIndexOf('\n', index - 1)
}
