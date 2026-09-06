package ai.rever.boss.components.dashboard.sections

import ai.rever.boss.plugin.ui.BossTheme
import ai.rever.boss.updater.UpdateCoordinator
import ai.rever.boss.updater.UpdateSettings
import ai.rever.boss.updater.UpdateSettingsManager
import ai.rever.boss.updater.UpdateState
import ai.rever.boss.updater.VersionInfo
import ai.rever.boss.updater.VersionListManager
import ai.rever.boss.updater.VersionSelectionDialog
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.Surface
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.DisposableEffect
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.window.Dialog

/** How many recent releases the feed shows before "View all" takes over. */
private const val WHATS_NEW_LIMIT = 5

/**
 * The Dashboard "What's New" feed: the most recent BOSS releases, so new capabilities are
 * discoverable on the home screen rather than only through the update dialog at update time.
 *
 * **Degrades to nothing, never to an error.** The section returns early - drawing no header and no
 * strip - whenever there is nothing to show: offline, still loading, a fetch error, or genuinely no
 * releases. The home screen must stay calm, so a failed release fetch is silence, not a red banner.
 * That also covers the browser plugin's `about:blank` copy of the dashboard, which composes
 * `HomeScreen()` with no callbacks: this section takes none, reads process-wide singletons, and
 * simply shows the same feed there.
 *
 * Data comes from [VersionListManager] (the same 1-hour-cached source the update dialog's version
 * list uses), so mounting this adds no fetch beyond the one already made on demand. It also
 * force-refreshes when the update coordinator reports a new release, which is the app's existing
 * Supabase-Realtime-driven signal, so a release published while the app is open reaches the feed.
 */
@Composable
fun WhatsNewSection() {
    val coordinator = UpdateCoordinator.instance
    val versionListManager = remember { VersionListManager(coordinator.updateService) }
    val versions by versionListManager.versions.collectAsState()
    val isLoading by versionListManager.isLoading.collectAsState()
    val error by versionListManager.error.collectAsState()
    val updateState by coordinator.updateState.collectAsState()

    // Snapshot the last-seen marker at first composition so a badge does not vanish while the user
    // is looking at it; the stored marker is advanced separately below.
    val previouslySeen = remember { UpdateSettings.lastSeenReleaseVersion }

    WhatsNewFeedEffects(versionListManager, updateState, versions)

    // Nothing to show: hide entirely rather than render an empty or error state. isLoading and
    // error are read so the compiler keeps the collectors alive and so this reads as "hide unless
    // there is real content".
    if (versions.isEmpty() || isLoading || error != null) return

    val newBadges =
        remember(versions, previouslySeen) {
            newReleaseVersions(versions.map { it.version.toString() }, previouslySeen)
        }

    var expanded by remember { mutableStateOf<VersionInfo?>(null) }
    var showAll by remember { mutableStateOf(false) }

    DashboardSection(
        title = "What's New",
        subtitle = "Latest releases and improvements",
        actionText = "View all",
        onAction = { showAll = true },
    ) {
        Row(
            modifier =
                Modifier
                    .fillMaxWidth()
                    .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(BossTheme.space.md),
        ) {
            versions.take(WHATS_NEW_LIMIT).forEach { release ->
                ReleaseCard(
                    release = release,
                    isNew = release.version.toString() in newBadges,
                    onClick = { expanded = release },
                )
            }
        }
    }

    expanded?.let { release ->
        ReleaseNotesDialog(release = release, onDismiss = { expanded = null })
    }

    if (showAll) {
        VersionSelectionDialog(
            currentVersion = coordinator.currentVersion(),
            versions = versions,
            isLoading = isLoading,
            error = error,
            // Browse-only from the feed: opening the picker is for discovery, not for triggering a
            // downgrade. Selecting a version just closes it; the update flow stays in Settings,
            // which carries the downgrade confirmation this entry point deliberately does not.
            onVersionSelected = { showAll = false },
            onDismiss = { showAll = false },
        )
    }
}

/**
 * The feed's side effects, split out so [WhatsNewSection] stays short: fetch on mount (1-hour
 * cached), force-refresh on the Realtime-driven update signal, clean up the manager on dispose, and
 * advance the persisted "last seen" marker to the newest release now shown so its badge does not
 * return next launch. The marker is kept distinct from `lastDismissedVersion`: seeing a release in
 * the feed is not dismissing its update prompt.
 */
@Composable
private fun WhatsNewFeedEffects(
    versionListManager: VersionListManager,
    updateState: UpdateState,
    versions: List<VersionInfo>,
) {
    LaunchedEffect(versionListManager) { versionListManager.fetchVersions() }
    // Idle/UpToDate on first composition do not fetch, so this adds no cold-start request.
    LaunchedEffect(updateState) {
        if (updateState is UpdateState.UpdateAvailable) versionListManager.fetchVersions(forceRefresh = true)
    }
    DisposableEffect(versionListManager) {
        onDispose { versionListManager.cleanup() }
    }
    LaunchedEffect(versions) {
        val newest = versions.firstOrNull()?.version?.toString()
        if (newest != null && newest != UpdateSettings.lastSeenReleaseVersion) {
            UpdateSettings.lastSeenReleaseVersion = newest
            UpdateSettingsManager.saveSettings()
        }
    }
}

/**
 * One release, as a card in the feed strip: version, an optional "NEW" badge, the date, and a short
 * summary of the notes. Clicking opens the full notes.
 */
@Composable
private fun ReleaseCard(
    release: VersionInfo,
    isNew: Boolean,
    onClick: () -> Unit,
) {
    val colors = BossTheme.colors
    Surface(
        modifier =
            Modifier
                .width(260.dp)
                .clip(RoundedCornerShape(10.dp))
                .clickable(onClick = onClick),
        color = colors.ink,
        shape = RoundedCornerShape(10.dp),
        border = androidx.compose.foundation.BorderStroke(1.dp, colors.line),
        elevation = 0.dp,
    ) {
        Column(modifier = Modifier.padding(14.dp)) {
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(
                    text = "v${release.version}",
                    color = colors.textPrimary,
                    fontSize = 15.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                if (isNew) {
                    Spacer(Modifier.width(8.dp))
                    Box(
                        modifier =
                            Modifier
                                .clip(RoundedCornerShape(4.dp))
                                .background(colors.data)
                                .padding(horizontal = 6.dp, vertical = 1.dp),
                    ) {
                        Text(text = "NEW", color = colors.onData, fontSize = 10.sp, fontWeight = FontWeight.Bold)
                    }
                }
            }
            if (release.releaseDate.isNotBlank()) {
                Spacer(Modifier.height(2.dp))
                Text(text = release.releaseDate, color = colors.textSecondary, fontSize = 11.sp)
            }
            Spacer(Modifier.height(8.dp))
            Text(
                text = releaseSummary(release.releaseNotes),
                color = colors.textSecondary,
                fontSize = 12.sp,
                maxLines = 3,
                overflow = TextOverflow.Ellipsis,
            )
        }
    }
}

/** Full release notes for one version, shown when a card is clicked. */
@Composable
private fun ReleaseNotesDialog(
    release: VersionInfo,
    onDismiss: () -> Unit,
) {
    val colors = BossTheme.colors
    Dialog(onDismissRequest = onDismiss) {
        Surface(
            modifier = Modifier.width(560.dp).heightIn(max = 560.dp),
            shape = RoundedCornerShape(12.dp),
            color = colors.panel,
            border = androidx.compose.foundation.BorderStroke(1.dp, colors.line),
            elevation = 8.dp,
        ) {
            Column(modifier = Modifier.padding(20.dp)) {
                Text(
                    text = "v${release.version}",
                    color = colors.textPrimary,
                    fontSize = 18.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                if (release.releaseDate.isNotBlank()) {
                    Spacer(Modifier.height(2.dp))
                    Text(text = release.releaseDate, color = colors.textSecondary, fontSize = 12.sp)
                }
                Spacer(Modifier.height(12.dp))
                Text(
                    text = release.releaseNotes.ifBlank { "No release notes for this version." },
                    color = colors.textSecondary,
                    fontSize = 13.sp,
                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .heightIn(max = 440.dp)
                            .verticalScroll(rememberScrollState()),
                )
            }
        }
    }
}

/**
 * The versions (as strings) that are newer than the last one the user saw, so they can carry a
 * "NEW" badge.
 *
 * Pure and string-only on purpose: [orderedVersions] is the newest-first list `VersionListManager`
 * already produces (`sortedByDescending`), so "newer than last seen" is "appears before last seen",
 * with no version parsing to get wrong. Two boundaries matter and both fail closed toward showing
 * FEWER badges, because a spurious "NEW" on an old release is the worse error:
 *
 *  - a null [lastSeen] is a fresh install, which badges nothing rather than every historical
 *    release at once;
 *  - a [lastSeen] no longer in the fetched window returns nothing rather than badging the whole
 *    list, since its true position is unknown.
 */
internal fun newReleaseVersions(
    orderedVersions: List<String>,
    lastSeen: String?,
): Set<String> {
    // -1 covers both "nothing seen yet" and "last seen fell out of the window"; index 0 means the
    // newest is already seen. Only a position strictly inside the list badges the entries above it.
    val index = lastSeen?.let(orderedVersions::indexOf) ?: -1
    return if (index <= 0) emptySet() else orderedVersions.take(index).toSet()
}

/**
 * A one-line summary of release notes for a card: the first line with content, stripped of the
 * markdown markers a heading or bullet starts with.
 *
 * The notes are markdown, and the first meaningful line is usually a heading or the first bullet.
 * This is not a markdown renderer - it only makes a card legible; the full notes render in the
 * dialog. Empty in, a fallback string out, so a card is never blank.
 */
internal fun releaseSummary(notes: String): String {
    val firstContentLine =
        notes
            .lineSequence()
            .map { it.trim() }
            .firstOrNull { it.isNotEmpty() }
            ?: return "See release notes"
    return firstContentLine.trimStart('#', '-', '*', '>', ' ').ifBlank { "See release notes" }
}
