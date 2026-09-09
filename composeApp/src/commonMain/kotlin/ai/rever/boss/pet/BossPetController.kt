package ai.rever.boss.pet

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * The state machine behind the floating BOSS pet.
 *
 * This is the **integration point** for the whole feature: anything that starts a long-running
 * action (an AI agent turn, a build, a plugin install) calls [taskStarted] and later exactly one of
 * [taskFinished] / [taskFailed], and the pet reflects it. The class is deliberately free of Compose
 * and coroutines timers so its every transition is a pure function of the calls made to it - which
 * is what [ai.rever.boss.pet.BossPetControllerTest] pins.
 *
 * **Tasks are tracked by id, and the count is a set, not an integer.** A caller that reports the
 * same task finished twice (a retry that races its own completion, say) must not drive the active
 * count negative and strand the pet in [BossPetMood.Working] forever, so finishing an id that was
 * never started, or was already finished, is a no-op for the count. Ref-counting by id rather than
 * by a bare number is the same choice `BrowserHandleImpl.composedSurfaces` documents for the same
 * failure mode.
 *
 * **The active count and the announcement are independent.** A [BossPetMood.Completed] or
 * [BossPetMood.Failed] announces the task that just ended, but tasks that are still running keep the
 * pet informed: dismissing an announcement returns to [BossPetMood.Working] when work remains, not
 * to [BossPetMood.Idle]. That is why [dismissAnnouncement] and [onIdleTimeout] both consult the live
 * set rather than assuming idle.
 */
class BossPetController {
    private val activeTasks = mutableSetOf<String>()

    private val _mood = MutableStateFlow<BossPetMood>(BossPetMood.Idle)

    /** The current mood, for the window to render. Never null; starts [BossPetMood.Idle]. */
    val mood: StateFlow<BossPetMood> = _mood.asStateFlow()

    /**
     * Record that a task with [id] has started. Idempotent: starting an id already running only
     * updates the count if it was genuinely new. Overrides any standing announcement, because new
     * work is more current than an old "finished".
     */
    @Synchronized
    fun taskStarted(id: String) {
        activeTasks.add(id)
        _mood.value = BossPetMood.Working(activeTasks.size)
    }

    /**
     * Record that [id] finished successfully. [label] is what the pet announces (e.g.
     * "Build finished"). Finishing an id that is not active does not change the count, but it still
     * announces - a caller that tracked the work itself and only tells the pet at the end is a valid
     * use, and swallowing that announcement would make the pet useless to it.
     */
    @Synchronized
    fun taskFinished(
        id: String,
        label: String,
    ) {
        activeTasks.remove(id)
        _mood.value = BossPetMood.Completed(label)
    }

    /**
     * Record that [id] failed. [label] names it. The resulting [BossPetMood.Failed] does not
     * auto-dismiss (see [onIdleTimeout]); a failure stays until acknowledged.
     */
    @Synchronized
    fun taskFailed(
        id: String,
        label: String,
    ) {
        activeTasks.remove(id)
        _mood.value = BossPetMood.Failed(label)
    }

    /**
     * Dismiss a standing [BossPetMood.Completed] or [BossPetMood.Failed] - the user clicked the pet,
     * or the completion toast timed out. Returns to [BossPetMood.Working] if tasks are still running,
     * otherwise [BossPetMood.Idle]. A no-op while already idle or working, so a stray dismiss cannot
     * clear a live working count.
     */
    @Synchronized
    fun dismissAnnouncement() {
        val current = _mood.value
        if (current is BossPetMood.Completed || current is BossPetMood.Failed) {
            _mood.value = restingMood()
        }
    }

    /**
     * The auto-idle timer fired. Clears **only** a [BossPetMood.Completed] with no work left - a
     * success the user has had time to see. [BossPetMood.Failed] is deliberately immune: it clears
     * only on an explicit [dismissAnnouncement], so a failure is never swept away on a timer the user
     * was not watching. [BossPetMood.Working] is left alone because live work outranks a stale
     * timer.
     */
    @Synchronized
    fun onIdleTimeout() {
        if (_mood.value is BossPetMood.Completed && activeTasks.isEmpty()) {
            _mood.value = BossPetMood.Idle
        }
    }

    private fun restingMood(): BossPetMood =
        if (activeTasks.isEmpty()) BossPetMood.Idle else BossPetMood.Working(activeTasks.size)
}
