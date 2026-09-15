package ai.rever.boss.updater

/**
 * Whether the app-update prompt should be on screen right now.
 *
 * The update prompt is the one dialog that appears on its own timer (a background update check
 * finishing) rather than in response to the user. On the heavyweight-overlay path (Windows), every
 * modal is a separate always-on-top window, and two of them stacked is the state BossConsole#696
 * reports as leaving BOSS unusable. So the prompt yields to any OTHER heavyweight modal: it does not
 * open over one, and it steps aside when one opens over it. The update banner still shows meanwhile,
 * and the prompt reappears once the other modal closes.
 *
 * [openHeavyweightModals] is the total from [ai.rever.boss.components.overlays.HeavyweightModalRegistry],
 * which counts the update prompt itself while it is up - so its own window is subtracted out via
 * [updateDialogShowing], leaving the count of modals that are NOT this prompt. On the lightweight
 * path the count is always 0 and this reduces to the previous condition, so nothing changes there.
 */
internal fun shouldShowUpdateDialog(
    wantDialog: Boolean,
    isOwner: Boolean,
    updateAvailable: Boolean,
    openHeavyweightModals: Int,
    updateDialogShowing: Boolean,
): Boolean {
    if (!wantDialog || !isOwner || !updateAvailable) return false
    val otherModals = openHeavyweightModals - if (updateDialogShowing) 1 else 0
    return otherModals <= 0
}
