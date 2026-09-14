package ai.rever.boss.services.importer

import org.w3c.dom.Document
import org.w3c.dom.Element
import org.xml.sax.InputSource
import java.io.StringReader
import javax.xml.parsers.DocumentBuilderFactory

/**
 * Reads a KeePass 2.x plaintext XML export (`File > Export > KeePass XML (2.x)`).
 *
 * The `.kdbx` database itself is encrypted binary and needs the user's master
 * key, so it is out of scope; the XML export writes the entries in the clear,
 * which is what a migrating user produces. The shape:
 *
 * ```xml
 * <KeePassFile><Root><Group>
 *   <Entry>
 *     <String><Key>Title</Key><Value>Example</Value></String>
 *     <String><Key>UserName</Key><Value>john</Value></String>
 *     <String><Key>Password</Key><Value>hunter2</Value></String>
 *     <String><Key>URL</Key><Value>https://example.com</Value></String>
 *   </Entry>
 *   <Group> … nested groups … </Group>
 * </Group></Root></KeePassFile>
 * ```
 *
 * Two format traps this gets right:
 *
 * - **History is not descended into.** An `<Entry>` can hold a `<History>` of its
 *   own past versions, each a full `<Entry>`; a naive "every Entry" walk would
 *   import a credential once per revision. This reads only an entry's direct
 *   `<String>` children and never recurses into an entry.
 * - **The Recycle Bin is skipped.** Deleted entries live in a group whose UUID
 *   the `<Meta>` block names; importing them would resurrect passwords the user
 *   threw away.
 *
 * Parses untrusted XML, so external entities and DTDs are disabled (XXE). Handles
 * plaintext passwords: this parses and returns, and never logs a value.
 */
object KeePassXmlParser {
    /** UUID KeePass writes when the Recycle Bin is unset (16 zero bytes, Base64). */
    private const val EMPTY_UUID = "AAAAAAAAAAAAAAAAAAAAAA=="

    /**
     * Every credential in [text], or an empty list when it is not a KeePass XML
     * export or cannot be parsed.
     */
    fun parse(text: String): List<ImportedPassword> {
        val doc = runCatching { secureDocument(text) }.getOrNull()
        val root =
            doc?.documentElement?.takeIf { it.tagName.equals("KeePassFile", ignoreCase = true) }
                ?: return emptyList()

        val out = mutableListOf<ImportedPassword>()
        childElement(root, "Root")?.let { collectFrom(it, recycleBinUuid(root), out) }
        return out
    }

    /** A cheap sniff for routing: the root element's name. */
    fun looksLikeKeePass(text: String): Boolean = text.contains("<KeePassFile", ignoreCase = true)

    /** Walk [node]'s child groups and entries, skipping the Recycle Bin group. */
    private fun collectFrom(
        node: Element,
        recycleBin: String?,
        out: MutableList<ImportedPassword>,
    ) {
        for (child in childElements(node)) {
            when (child.tagName) {
                "Group" -> {
                    val uuid = childElement(child, "UUID")?.textContent?.trim()
                    // Skip deleted entries; descend into every other group.
                    if (uuid == null || uuid != recycleBin) collectFrom(child, recycleBin, out)
                }

                "Entry" -> {
                    entryToPassword(child)?.let(out::add)
                }
            }
        }
    }

    /** One entry's `<String>` fields to a credential, or null when it has no password. */
    private fun entryToPassword(entry: Element): ImportedPassword? {
        val fields = HashMap<String, String>()
        for (field in childElements(entry)) {
            // Only direct String children: this deliberately does not enter <History>.
            if (field.tagName == "String") {
                val key = childElement(field, "Key")?.textContent?.trim()
                if (!key.isNullOrEmpty()) {
                    fields[key] = childElement(field, "Value")?.textContent ?: ""
                }
            }
        }

        // Edge whitespace is part of a password, not formatting, so it is not trimmed.
        val password = fields["Password"].orEmpty()
        if (password.isEmpty()) return null

        val url = fields["URL"]?.trim().orEmpty()
        val website = url.ifEmpty { fields["Title"]?.trim().orEmpty() }
        return ImportedPassword(
            website = website,
            username = fields["UserName"]?.trim().orEmpty(),
            password = password,
            notes = fields["Notes"]?.trim()?.ifEmpty { null },
        )
    }

    /** The Recycle Bin group's UUID when the bin is enabled and set, else null. */
    private fun recycleBinUuid(root: Element): String? {
        val meta = childElement(root, "Meta") ?: return null
        val enabled = childElement(meta, "RecycleBinEnabled")?.textContent?.trim().equals("True", ignoreCase = true)
        val uuid = childElement(meta, "RecycleBinUUID")?.textContent?.trim()
        return uuid?.takeIf { enabled && it.isNotEmpty() && it != EMPTY_UUID }
    }

    /** Parse [text] with external entities and DTDs disabled (XXE hardening). */
    private fun secureDocument(text: String): Document {
        val factory = DocumentBuilderFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        factory.isXIncludeAware = false
        factory.isExpandEntityReferences = false
        return factory.newDocumentBuilder().parse(InputSource(StringReader(text)))
    }

    private fun childElements(node: Element): List<Element> {
        val children = node.childNodes
        return (0 until children.length).mapNotNull { children.item(it) as? Element }
    }

    private fun childElement(
        node: Element,
        name: String,
    ): Element? = childElements(node).firstOrNull { it.tagName == name }
}
