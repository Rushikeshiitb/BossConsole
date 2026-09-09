package ai.rever.boss.pet

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * App-global task bookkeeping. Unacknowledged results are ordered by arrival and carry their task id,
 * so another task starting or finishing cannot erase a failure or misattribute a completion.
 * Producers must use distinct ids for concurrent tasks. Reusing an id starts a new run.
 */
class BossPetController {
    private val activeTasks = mutableSetOf<String>()
    private val announcements = linkedMapOf<Long, BossPetMood>()
    private var nextAnnouncement = 0L
    private val _mood = MutableStateFlow<BossPetMood>(BossPetMood.Idle)
    val mood: StateFlow<BossPetMood> = _mood.asStateFlow()

    @Synchronized
    fun taskStarted(id: String) {
        activeTasks.add(id)
        publish()
    }

    @Synchronized
    fun taskFinished(
        id: String,
        label: String,
    ) {
        if (!activeTasks.remove(id) && hasAnnouncement(id, failure = false)) return
        val sequence = nextAnnouncement++
        announcements[sequence] = BossPetMood.Completed(label, id, sequence)
        publish()
    }

    @Synchronized
    fun taskFailed(
        id: String,
        label: String,
    ) {
        if (!activeTasks.remove(id) && hasAnnouncement(id, failure = true)) return
        val sequence = nextAnnouncement++
        announcements[sequence] = BossPetMood.Failed(label, id, sequence)
        publish()
    }

    /** End activity without a result message, for cancelled work or an update check finding nothing. */
    @Synchronized
    fun taskStopped(id: String) {
        activeTasks.remove(id)
        publish()
    }

    @Synchronized
    fun dismissAnnouncement() {
        announcements.keys.firstOrNull()?.let { announcements.remove(it) }
        publish()
    }

    /** Advance successes even while other tasks run. Failures require explicit acknowledgement. */
    @Synchronized
    fun onIdleTimeout() {
        if (_mood.value is BossPetMood.Completed) dismissAnnouncement()
    }

    private fun hasAnnouncement(
        id: String,
        failure: Boolean,
    ): Boolean =
        announcements.values.any {
            when (it) {
                is BossPetMood.Completed -> !failure && it.taskId == id
                is BossPetMood.Failed -> failure && it.taskId == id
                else -> false
            }
        }

    private fun publish() {
        _mood.value =
            announcements.values.firstOrNull()
                ?: if (activeTasks.isEmpty()) BossPetMood.Idle else BossPetMood.Working(activeTasks.size)
    }
}
