package ai.rever.boss.components.dashboard.cards

import ai.rever.boss.plugin.ui.BossTheme
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.spring
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.hoverable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsHoveredAsState
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Card for one release in the Dashboard "What's new" feed: version, date, a one-line summary, and a
 * NEW badge when the release is newer than what the user has already seen.
 *
 * Takes primitives rather than a `VersionInfo` / feed model on purpose - this `cards` package is
 * imported by the home screen, and taking the domain type would make the dependency point back the
 * other way. The caller maps its model to these strings.
 */
@Composable
fun ReleaseCard(
    versionLabel: String,
    date: String,
    summary: String,
    isNew: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier,
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isHovered by interactionSource.collectIsHoveredAsState()

    val scale by animateFloatAsState(
        targetValue = if (isHovered) 1.02f else 1f,
        animationSpec = spring(dampingRatio = 0.6f),
    )
    val backgroundColor = if (isHovered) BossTheme.colors.signalWash else BossTheme.colors.raised
    val cardShape = RoundedCornerShape(12.dp)

    Column(
        modifier =
            modifier
                .width(240.dp)
                .scale(scale)
                .clip(cardShape)
                .background(color = backgroundColor)
                .clickable { onClick() }
                .hoverable(interactionSource)
                .padding(14.dp),
        verticalArrangement = Arrangement.spacedBy(6.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = versionLabel,
                color = BossTheme.colors.textPrimary,
                fontSize = 14.sp,
                fontWeight = FontWeight.SemiBold,
            )
            if (isNew) {
                NewBadge()
            }
        }

        if (date.isNotBlank()) {
            Text(
                text = date,
                color = BossTheme.colors.textSecondary,
                fontSize = 11.sp,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis,
            )
        }

        // Fixed height so cards in the strip line up whether or not a summary is present.
        Text(
            text = summary,
            color = BossTheme.colors.textSecondary,
            fontSize = 12.sp,
            maxLines = 2,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.fillMaxWidth().height(34.dp),
        )
    }
}

@Composable
private fun NewBadge() {
    Text(
        text = "NEW",
        color = BossTheme.colors.onSignal,
        fontSize = 9.sp,
        fontWeight = FontWeight.Bold,
        modifier =
            Modifier
                .clip(RoundedCornerShape(4.dp))
                .background(BossTheme.colors.signal)
                .padding(horizontal = 6.dp, vertical = 2.dp),
    )
}
