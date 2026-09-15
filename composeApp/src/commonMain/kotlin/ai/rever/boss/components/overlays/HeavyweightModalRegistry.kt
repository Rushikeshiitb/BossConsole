package ai.rever.boss.components.overlays

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue

/**
 * How many heavyweight MODAL windows are open right now.
 *
 * Distinct from [OverlayConfig.openHeavyweightPopups]: that one counts anchored popups (dropdowns,
 * context menus) so a modal can tell a child overlay taking focus from a real click-away. This one
 * counts the modals themselves, and it exists for a different reason - so an AUTONOMOUS dialog can
 * refuse to appear on top of a modal the user is already dealing with, and so a modal opening later
 * can push an autonomous one out of the way rather than stacking a second always-on-top window over
 * it.
 *
 * The concrete failure is BossConsole#696 (Windows): the app-update prompt is the one dialog that
 * appears on its own timer rather than in response to the user, so it can pop up over a dialog the
 * user is filling in, or another dialog can open over it. Two always-on-top heavyweight modal
 * windows stacked is the state that report describes as leaving BOSS unusable. Gating the update
 * prompt on this count keeps it from ever being the second modal, in either direction.
 *
 * Snapshot state, unlike the popup counter, precisely because a composable (the update-dialog gate)
 * reads it and must recompose when it changes - the popup counter is only ever read imperatively
 * inside a focus listener, so a plain Int suffices there.
 *
 * **UI-thread only.** The `++`/`--` on a snapshot Int are not atomic; every writer is a Compose
 * `DisposableEffect` on the UI thread ([HeavyweightModal]), so the contract holds by construction.
 * It stays 0 on the lightweight (OFF_SCREEN) path, where modals are ordinary Compose `Dialog`s that
 * Compose stacks correctly on its own - so this changes nothing there.
 */
object HeavyweightModalRegistry {
    var openCount: Int by mutableStateOf(0)
        private set

    /** Called by [HeavyweightModal] when its window appears. UI thread only. */
    fun acquire() {
        openCount += 1
    }

    /** Called by [HeavyweightModal] when its window is disposed. UI thread only. */
    fun release() {
        openCount = (openCount - 1).coerceAtLeast(0)
    }
}
