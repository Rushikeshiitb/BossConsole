package ai.rever.boss.plugin.ui

import androidx.compose.material.Text
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.junit4.createComposeRule
import org.junit.Rule
import org.junit.Test

/**
 * Pins the accessibility fixes for the heavyweight modal card (issue #143): the card is announced as
 * a dialog, and its click-swallow no longer makes the whole card read as a button.
 *
 * Tested through [ScrimmedModalContent] directly for the same reason [ModalInputArmingTest] is - the
 * heavyweight path is a real OS window a test scene cannot host, but the card's modifier chain is the
 * same either way.
 */
class ScrimmedModalSemanticsTest {
    @get:Rule
    val rule = createComposeRule()

    @Test
    fun `the modal card carries dialog semantics and no button role`() {
        rule.setContent {
            ScrimmedModalContent(dismissOnClickOutside = true, onDismissRequest = {}) {
                Text("Dialog body")
            }
        }

        val dialogNode =
            rule.onNode(
                SemanticsMatcher.keyIsDefined(SemanticsProperties.IsDialog),
                useUnmergedTree = true,
            )
        // The heavyweight card declares dialog(): the lightweight Dialog path announces one and this
        // path did not.
        dialogNode.assertExists("the modal card should carry dialog() semantics")
        // The click-swallow used clickable(onClick = {}), which gave the card an OnClick action and a
        // Button role, so a screen reader announced the whole dialog as a button. The swallow is a
        // bare detectTapGestures now, which adds no semantics.
        dialogNode.assert(SemanticsMatcher.keyNotDefined(SemanticsActions.OnClick))
    }
}
