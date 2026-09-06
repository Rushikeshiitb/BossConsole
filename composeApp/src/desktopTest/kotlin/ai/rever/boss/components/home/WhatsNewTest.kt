package ai.rever.boss.components.home

import ai.rever.boss.updater.VersionInfo
import ai.rever.boss.utils.Version
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Pins the two pure decisions behind the Dashboard "What's new" feed: which releases carry a NEW
 * badge, and how a release-notes teaser is reduced to one line. Both are consumed inside a composable
 * whose failure is only visible on screen, so they are extracted and tested here.
 */
class WhatsNewTest {
    private fun release(
        major: Int,
        minor: Int,
        patch: Int,
        notes: String = "notes",
    ): VersionInfo =
        VersionInfo(
            version = Version(major, minor, patch),
            releaseDate = "2026-09-06",
            downloadSize = 0L,
            releaseNotes = notes,
            downloadUrl = "",
            isDraft = false,
            isPrerelease = false,
        )

    // VersionListManager hands these over already sorted descending, so the feed relies on that order.
    private val versions =
        listOf(
            release(9, 5, 8),
            release(9, 5, 7),
            release(9, 5, 6),
            release(9, 5, 5),
        )

    @Test
    fun `nothing is badged when no release has been seen yet`() {
        // First run / never-seen: a null lastSeen must badge nothing, or every release lights up NEW
        // the first time the feed is shown - the noise this marker exists to prevent.
        val entries = whatsNewEntries(versions, lastSeen = null)
        assertEquals(versions.size, entries.size)
        assertTrue(entries.none { it.isNew }, "a null lastSeen must not badge anything")
    }

    @Test
    fun `only releases strictly newer than the last seen version are badged`() {
        val entries = whatsNewEntries(versions, lastSeen = Version(9, 5, 6))

        // 9.5.8 and 9.5.7 are newer than 9.5.6; 9.5.6 itself (already seen) and 9.5.5 are not.
        assertEquals(listOf(true, true, false, false), entries.map { it.isNew })
    }

    @Test
    fun `the feed is capped at the limit, newest first`() {
        val many = (20 downTo 1).map { release(9, 5, it) }
        val entries = whatsNewEntries(many, lastSeen = null, limit = 5)

        assertEquals(5, entries.size)
        assertEquals(Version(9, 5, 20), entries.first().info.version)
        assertEquals(Version(9, 5, 16), entries.last().info.version)
    }

    @Test
    fun `a summary is the first non-empty line with leading markdown punctuation stripped`() {
        val notes =
            """

            # BossConsole 9.5.8

            - Fixed the toast overlay
            """.trimIndent()
        assertEquals("BossConsole 9.5.8", releaseSummary(notes))
    }

    @Test
    fun `a summary of blank notes is empty rather than punctuation`() {
        assertEquals("", releaseSummary("   \n\n  "))
        assertEquals("", releaseSummary(""))
    }
}
