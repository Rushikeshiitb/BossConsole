package ai.rever.boss.components.dashboard.sections

import kotlin.test.Test
import kotlin.test.assertEquals

/**
 * Pins the two pure decisions behind the "What's New" feed. Both are deliberately string-only so
 * they need no display and no `Version` construction: [newReleaseVersions] leans on the newest-first
 * order `VersionListManager` already guarantees.
 */
class WhatsNewSectionTest {
    private val ordered = listOf("9.5.8", "9.5.7", "9.5.6", "9.5.5")

    @Test
    fun `a fresh install badges nothing`() {
        // Null last-seen: badging every historical release at once would be noise, not news.
        assertEquals(emptySet(), newReleaseVersions(ordered, lastSeen = null))
    }

    @Test
    fun `nothing is new when the newest release has already been seen`() {
        assertEquals(emptySet(), newReleaseVersions(ordered, lastSeen = "9.5.8"))
    }

    @Test
    fun `only releases newer than the last seen are badged`() {
        // Seen 9.5.6, so 9.5.8 and 9.5.7 are new; 9.5.6 and older are not.
        assertEquals(setOf("9.5.8", "9.5.7"), newReleaseVersions(ordered, lastSeen = "9.5.6"))
    }

    @Test
    fun `a last-seen that fell out of the window badges nothing rather than the whole list`() {
        // Its true position is unknown, so failing closed avoids a screen full of false "NEW"s.
        assertEquals(emptySet(), newReleaseVersions(ordered, lastSeen = "9.0.0"))
    }

    @Test
    fun `the summary is the first content line, stripped of a markdown heading marker`() {
        assertEquals("Highlights", releaseSummary("# Highlights\n\n- Fixed a crash"))
    }

    @Test
    fun `the summary skips leading blank lines and strips a bullet marker`() {
        assertEquals("Fixed a crash on launch", releaseSummary("\n\n   - Fixed a crash on launch\nmore"))
    }

    @Test
    fun `blank notes fall back rather than rendering an empty card line`() {
        assertEquals("See release notes", releaseSummary(""))
        assertEquals("See release notes", releaseSummary("   \n  \n"))
        assertEquals("See release notes", releaseSummary("###"))
    }
}
