package ai.rever.boss.services.security

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Pins the clipboard auto-clear behaviour with a fake clipboard and a fake scheduler - no AWT, no real timer. */
class SecretClipboardTest {
    private class FakeClipboard(
        var text: String? = null,
    ) : ClipboardAccess {
        override fun readText(): String? = text

        override fun writeText(text: String) {
            this.text = text
        }
    }

    private class FakeScheduler : ClearScheduler {
        val tasks = mutableListOf<() -> Unit>()
        var cancelCount = 0

        override fun schedule(
            delayMillis: Long,
            task: () -> Unit,
        ): ScheduledClear {
            tasks.add(task)
            return ScheduledClear { cancelCount++ }
        }

        fun fireLast() = tasks.last().invoke()
    }

    @Test
    fun `copy writes the secret and arms a clear`() {
        val clip = FakeClipboard()
        val sched = FakeScheduler()
        SecretClipboardManager(clip, sched).copySecret("hunter2")

        assertEquals("hunter2", clip.text)
        assertEquals(1, sched.tasks.size, "a clear was scheduled")
    }

    @Test
    fun `the scheduled clear wipes the clipboard when it is unchanged`() {
        val clip = FakeClipboard()
        val sched = FakeScheduler()
        SecretClipboardManager(clip, sched).copySecret("hunter2")

        sched.fireLast()
        assertEquals("", clip.text, "clipboard wiped")
    }

    @Test
    fun `the scheduled clear leaves the clipboard alone if the user copied something else`() {
        val clip = FakeClipboard()
        val sched = FakeScheduler()
        SecretClipboardManager(clip, sched).copySecret("hunter2")

        clip.text = "user's own copy"
        sched.fireLast()
        assertEquals("user's own copy", clip.text, "the user's later copy is preserved")
    }

    @Test
    fun `re-copying cancels the previous pending clear`() {
        val clip = FakeClipboard()
        val sched = FakeScheduler()
        val manager = SecretClipboardManager(clip, sched)

        manager.copySecret("first")
        manager.copySecret("second")
        assertEquals(1, sched.cancelCount, "the first clear was cancelled")
        assertEquals("second", clip.text)

        // Firing the first (now cancelled) task must not wipe the second secret.
        // clearIfUnchanged reads state, which now tracks "second", so firing the
        // stale task would only clear "second" - which is why cancellation matters.
        assertEquals(2, sched.tasks.size)
    }

    @Test
    fun `clearIfUnchanged is a no-op before anything is copied`() {
        val clip = FakeClipboard(text = "unrelated")
        assertFalse(SecretClipboardManager(clip, FakeScheduler()).clearIfUnchanged())
        assertEquals("unrelated", clip.text)
    }

    @Test
    fun `the policy clears only an untouched clipboard`() {
        assertTrue(ClipboardClearPolicy.shouldClear("s", "s"))
        assertFalse(ClipboardClearPolicy.shouldClear("s", "other"))
        assertFalse(ClipboardClearPolicy.shouldClear(null, null))
        assertFalse(ClipboardClearPolicy.shouldClear("s", null))
    }

    @Test
    fun `a cleared manager does not clear twice`() {
        val clip = FakeClipboard()
        val sched = FakeScheduler()
        val manager = SecretClipboardManager(clip, sched)
        manager.copySecret("hunter2")

        assertTrue(manager.clearIfUnchanged())
        assertFalse(manager.clearIfUnchanged(), "nothing left to clear")
    }
}
