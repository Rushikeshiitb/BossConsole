package ai.rever.boss.services.security

import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.awt.datatransfer.StringSelection

/**
 * Auto-clearing clipboard for copied secrets - standard password-manager hygiene
 * BOSS did not have. When a password or a one-time code is copied it should not sit
 * on the clipboard indefinitely, where the next app to read it (or a clipboard
 * history tool) can lift it.
 *
 * The one non-obvious rule, and the reason this is a unit and not a one-liner: a
 * scheduled clear must **only** wipe the clipboard if it still holds what we put
 * there. If the user copied something else in the meantime, clearing would destroy
 * their data. That decision is [ClipboardClearPolicy], kept pure; the manager wires
 * it to an injected clipboard and scheduler so the whole flow is testable with no
 * AWT and no real timer.
 */

/** The clipboard, abstracted so [SecretClipboardManager] can be tested without AWT. */
interface ClipboardAccess {
    fun readText(): String?

    fun writeText(text: String)
}

/** A scheduled clear that can be cancelled if the secret is re-copied first. */
fun interface ScheduledClear {
    fun cancel()
}

/** Runs [task] after [delayMillis]; the returned handle cancels it. */
fun interface ClearScheduler {
    fun schedule(
        delayMillis: Long,
        task: () -> Unit,
    ): ScheduledClear
}

/** Whether a scheduled clear should fire: only when the clipboard is unchanged since we wrote it. */
object ClipboardClearPolicy {
    fun shouldClear(
        copied: String?,
        current: String?,
    ): Boolean = copied != null && current == copied
}

/**
 * Copies a secret and schedules it to be wiped after [clearDelayMillis], wiping
 * only if the clipboard still holds it.
 */
class SecretClipboardManager(
    private val clipboard: ClipboardAccess,
    private val scheduler: ClearScheduler,
    private val clearDelayMillis: Long = DEFAULT_CLEAR_DELAY_MILLIS,
) {
    private var lastCopied: String? = null
    private var pending: ScheduledClear? = null

    /** Write [secret] to the clipboard and (re)arm the auto-clear. */
    fun copySecret(secret: String) {
        // Re-copying supersedes any earlier pending clear, so a slow first timer
        // cannot wipe a fresh copy.
        pending?.cancel()
        clipboard.writeText(secret)
        lastCopied = secret
        pending = scheduler.schedule(clearDelayMillis) { clearIfUnchanged() }
    }

    /**
     * Wipe the clipboard if it still holds the last copied secret. Returns true if
     * it cleared, false if the user had copied something else (which is left alone).
     */
    fun clearIfUnchanged(): Boolean {
        val copied = lastCopied ?: return false
        val cleared = ClipboardClearPolicy.shouldClear(copied, clipboard.readText())
        if (cleared) {
            clipboard.writeText("")
            lastCopied = null
            pending = null
        }
        return cleared
    }

    companion object {
        /** Chrome and 1Password default to a 30-second clipboard clear; this matches. */
        const val DEFAULT_CLEAR_DELAY_MILLIS = 30_000L
    }
}

/** The real system clipboard, via AWT. */
class AwtClipboardAccess : ClipboardAccess {
    private val clipboard get() = Toolkit.getDefaultToolkit().systemClipboard

    override fun readText(): String? =
        runCatching {
            clipboard.getData(DataFlavor.stringFlavor) as? String
        }.getOrNull()

    override fun writeText(text: String) {
        clipboard.setContents(StringSelection(text), null)
    }
}
