package ai.rever.boss.pet

import ai.rever.boss.updater.UpdateState

/** Observes only the updater's task; quiet updater transitions must not dismiss other results. */
internal fun reportPetUpdateState(
    controller: BossPetController,
    state: UpdateState,
) {
    when (state) {
        is UpdateState.CheckingForUpdates,
        is UpdateState.Downloading,
        is UpdateState.Installing,
        -> controller.taskStarted(UPDATE_TASK_ID)
        is UpdateState.ReadyToInstall -> controller.taskFinished(UPDATE_TASK_ID, "Update ready to install")
        is UpdateState.RestartRequired -> controller.taskFinished(UPDATE_TASK_ID, "Update installed - restart BOSS")
        is UpdateState.Error -> controller.taskFailed(UPDATE_TASK_ID, "Update failed")
        is UpdateState.Idle,
        is UpdateState.UpToDate,
        is UpdateState.UpdateAvailable,
        -> controller.taskStopped(UPDATE_TASK_ID)
    }
}

private const val UPDATE_TASK_ID = "app-update"
