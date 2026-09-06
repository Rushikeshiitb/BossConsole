package ai.rever.boss.components.home

import ai.rever.boss.components.dashboard.cards.ReleaseCard
import ai.rever.boss.components.dashboard.sections.DashboardSection
import ai.rever.boss.plugin.ui.BossAlertDialog
import ai.rever.boss.plugin.ui.BossTheme
import ai.rever.boss.updater.NotesBlockView
import ai.rever.boss.updater.UpdateSettings
import ai.rever.boss.updater.UpdateSettingsManager
import ai.rever.boss.updater.VersionInfo
import ai.rever.boss.updater.VersionSelectionDialog
import ai.rever.boss.updater.parseReleaseNotes
import ai.rever.boss.utils.AppVersion
import ai.rever.boss.utils.Version
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.widthIn
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.Text
import androidx.compose.material.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Dashboard "What's new" feed: recent releases and what changed in them, so features ship visibly
 * rather than only through the update dialog at update time.
 *
 * Hides itself whenever there is nothing to show - not yet fetched, offline, or a fetch error - so
 * the Dashboard never carries an error state for this. The version list, the markdown renderer and
 * the "View all" dialog are all reused from the updater; the only new persisted state is
 * [UpdateSettings.lastSeenReleaseVersion], which drives the NEW badge. Lives in its own file rather
 * than beside the other home sections only to keep `HomeScreen` under detekt's per-file function cap.
 */
@Composable
internal fun WhatsNewSection() {
    val manager = WhatsNewVersions.manager
    val versions by manager.versions.collectAsState()
    val isLoading by manager.isLoading.collectAsState()
    val error by manager.error.collectAsState()

    // Best-effort refresh on mount; the manager's own 1-hour cache means repeated opens do not
    // re-fetch. On failure `versions` stays empty and the section hides - never an error state.
    LaunchedEffect(Unit) { manager.fetchVersions() }

    if (versions.isEmpty()) return

    // Read the marker ONCE, before advancing it below, so this session's badges reflect what the
    // user had not seen on entry rather than clearing the instant the section mounts.
    val lastSeen =
        remember {
            UpdateSettings.lastSeenReleaseVersion?.let { runCatching { Version.parse(it) }.getOrNull() }
        }
    val entries = remember(versions, lastSeen) { whatsNewEntries(versions, lastSeen) }

    // Advance the marker to the latest release so these stop being NEW on the next launch.
    AdvanceSeenMarker(versions.first().version)

    var notesFor by remember { mutableStateOf<VersionInfo?>(null) }
    var showAll by remember { mutableStateOf(false) }

    DashboardSection(
        title = "What's new",
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
            entries.forEach { entry ->
                ReleaseCard(
                    versionLabel = "v${entry.info.version}",
                    // Trim an ISO datetime to its date; a plain date passes through unchanged.
                    date = entry.info.releaseDate.substringBefore('T'),
                    summary = releaseSummary(entry.info.releaseNotes),
                    isNew = entry.isNew,
                    onClick = { notesFor = entry.info },
                )
            }
        }
    }

    notesFor?.let { info ->
        ReleaseNotesDialog(info = info, onDismiss = { notesFor = null })
    }

    if (showAll) {
        VersionSelectionDialog(
            currentVersion = AppVersion.CURRENT,
            versions = versions,
            isLoading = isLoading,
            error = error,
            // Read-only here: selecting a version opens its notes rather than starting a download.
            onVersionSelected = { info ->
                showAll = false
                notesFor = info
            },
            onDismiss = { showAll = false },
        )
    }
}

/**
 * Records [newest] as the last release the user has seen, so it and everything older stop carrying a
 * NEW badge on the next launch. A no-op when the marker is already current, to avoid a disk write on
 * every Dashboard open.
 */
@Composable
private fun AdvanceSeenMarker(newest: Version) {
    LaunchedEffect(newest) {
        if (UpdateSettings.lastSeenReleaseVersion != newest.toString()) {
            UpdateSettings.lastSeenReleaseVersion = newest.toString()
            UpdateSettingsManager.saveSettings()
        }
    }
}

/**
 * The full release notes for one version, rendered the same way the update dialog's "What's new"
 * does - through [parseReleaseNotes]/[NotesBlockView], falling back to plain lines when the markdown
 * cannot be parsed.
 */
@Composable
private fun ReleaseNotesDialog(
    info: VersionInfo,
    onDismiss: () -> Unit,
) {
    val notesBlocks =
        remember(info.releaseNotes) {
            runCatching { parseReleaseNotes(info.releaseNotes) }
                .getOrNull()
                ?.takeIf { it.isNotEmpty() }
        }
    BossAlertDialog(
        onDismissRequest = onDismiss,
        confirmButton = {
            TextButton(onClick = onDismiss) {
                Text("Close", color = BossTheme.colors.textSecondary, fontSize = 13.sp)
            }
        },
        modifier = Modifier.widthIn(min = 360.dp, max = 480.dp),
        title = {
            Text(
                "BossConsole v${info.version}",
                color = BossTheme.colors.textPrimary,
                fontSize = 16.sp,
                fontWeight = FontWeight.SemiBold,
            )
        },
        text = {
            Column(
                modifier = Modifier.heightIn(max = 320.dp).verticalScroll(rememberScrollState()),
                verticalArrangement = Arrangement.spacedBy(4.dp),
            ) {
                when {
                    notesBlocks != null -> {
                        notesBlocks.forEach { NotesBlockView(it) }
                    }

                    info.releaseNotes.isNotBlank() -> {
                        info.releaseNotes.lines().forEach { line ->
                            Text(line, color = BossTheme.colors.textSecondary, fontSize = 12.sp)
                        }
                    }

                    else -> {
                        Text("No release notes.", color = BossTheme.colors.textSecondary, fontSize = 12.sp)
                    }
                }
            }
        },
    )
}
