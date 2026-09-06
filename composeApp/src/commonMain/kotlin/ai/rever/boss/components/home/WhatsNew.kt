package ai.rever.boss.components.home

import ai.rever.boss.updater.UpdateCoordinator
import ai.rever.boss.updater.VersionInfo
import ai.rever.boss.updater.VersionListManager
import ai.rever.boss.utils.Version

/**
 * How many recent releases the Dashboard "What's new" feed shows before "View all". Kept small: the
 * strip is a teaser that sits above the fold, not the version history the "View all" dialog is for.
 */
internal const val WHATS_NEW_LIMIT = 5

/**
 * One release in the feed, paired with whether it should carry a NEW badge.
 *
 * A plain view model rather than a `VersionInfo` extension so the badge rule is decided once, in
 * [whatsNewEntries], and pinned by a test rather than recomputed at each render.
 */
internal data class WhatsNewEntry(
    val info: VersionInfo,
    val isNew: Boolean,
)

/**
 * The releases to show, newest first, each flagged NEW when it is newer than [lastSeen].
 *
 * [versions] arrives from [VersionListManager] already filtered (no drafts or pre-releases) and
 * sorted descending, so this only takes the head and decides the badge. Two rules the test pins:
 *
 *  - A null [lastSeen] badges NOTHING. It is the first-run / never-seen state, and painting every
 *    release NEW there is the noise this feature is meant to avoid - the feed advances the marker to
 *    the latest release the first time it is shown, so genuine future releases badge after that.
 *  - Only STRICTLY newer releases badge. The release the user is already on, and older ones, are not
 *    new to them.
 */
internal fun whatsNewEntries(
    versions: List<VersionInfo>,
    lastSeen: Version?,
    limit: Int = WHATS_NEW_LIMIT,
): List<WhatsNewEntry> =
    versions.take(limit).map { info ->
        WhatsNewEntry(info, isNew = lastSeen != null && info.version.isNewerThan(lastSeen))
    }

/**
 * A one-line summary of release notes for a card: the first non-empty line with any leading
 * markdown heading, bullet or quote punctuation stripped, or "" when there is nothing usable.
 *
 * Best-effort and deliberately dumb - the full, correctly rendered notes are one click away through
 * `parseReleaseNotes`; this only needs to give the card a readable teaser without pulling the
 * markdown parser into the strip.
 */
internal fun releaseSummary(notes: String): String {
    val line =
        notes
            .lineSequence()
            .map { it.trim() }
            .firstOrNull { it.isNotEmpty() }
            ?: return ""
    return line.trimStart('#', '-', '*', '>', ' ').trim()
}

/**
 * One shared [VersionListManager] for the feed, so opening the Dashboard repeatedly reuses the
 * manager's 1-hour cache instead of fetching every time.
 *
 * `by lazy` rather than eager: constructing it reads [UpdateCoordinator.instance], and nothing
 * should force that graph up until a window actually shows the feed. `VersionListManager` fetches
 * through the caller's coroutine scope and holds no scope of its own, so a process-wide holder is
 * safe - there is nothing here to leak when a window closes.
 */
internal object WhatsNewVersions {
    val manager: VersionListManager by lazy {
        VersionListManager(UpdateCoordinator.instance.updateService)
    }
}
