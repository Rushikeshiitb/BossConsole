package ai.rever.boss.pet

import ai.rever.boss.updater.UpdateState
import kotlin.test.Test
import kotlin.test.assertEquals

class BossPetUpdateStateTest {
    @Test
    fun `a routine update check cannot strand the pet working`() {
        val controller = BossPetController()
        reportPetUpdateState(controller, UpdateState.CheckingForUpdates)
        assertEquals(BossPetMood.Working(1), controller.mood.value)
        reportPetUpdateState(controller, UpdateState.UpToDate)
        assertEquals(BossPetMood.Idle, controller.mood.value)
    }

    @Test
    fun `quiet updater states cannot acknowledge another task failure`() {
        val controller = BossPetController()
        controller.taskFailed("build", "Build failed")
        reportPetUpdateState(controller, UpdateState.CheckingForUpdates)
        reportPetUpdateState(controller, UpdateState.Idle)
        assertEquals(BossPetMood.Failed("Build failed", "build"), controller.mood.value)
        controller.dismissAnnouncement()
        assertEquals(BossPetMood.Idle, controller.mood.value)
    }

    @Test
    fun `download progress counts once and completion clears activity`() {
        val controller = BossPetController()
        reportPetUpdateState(controller, UpdateState.Downloading(0.1f))
        reportPetUpdateState(controller, UpdateState.Downloading(0.5f))
        assertEquals(BossPetMood.Working(1), controller.mood.value)
        reportPetUpdateState(controller, UpdateState.ReadyToInstall("/tmp/update"))
        controller.dismissAnnouncement()
        assertEquals(BossPetMood.Idle, controller.mood.value)
    }

    @Test
    fun `an install failure survives even if the state flow skipped installing`() {
        val controller = BossPetController()
        reportPetUpdateState(controller, UpdateState.ReadyToInstall("/tmp/update"))
        reportPetUpdateState(controller, UpdateState.Error("Install failed"))
        controller.onIdleTimeout()
        assertEquals(BossPetMood.Failed("Update failed", "app-update", 1), controller.mood.value)
        controller.onIdleTimeout()
        assertEquals(BossPetMood.Failed("Update failed", "app-update", 1), controller.mood.value)
    }
}
