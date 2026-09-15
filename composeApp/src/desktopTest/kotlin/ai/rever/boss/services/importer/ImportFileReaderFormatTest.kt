package ai.rever.boss.services.importer

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Pins the format routing in [ImportFileReader.parseContent]: the new Bitwarden
 * JSON and KeePass XML paths are reached, and the pre-existing CSV path is not
 * disturbed.
 */
class ImportFileReaderFormatTest {
    @Test
    fun `routes a Bitwarden JSON export to the Bitwarden parser`() {
        val json =
            """
            { "encrypted": false, "items": [
              { "type": 1, "name": "Example",
                "login": { "uris": [ { "uri": "https://example.com" } ],
                           "username": "john", "password": "hunter2" } }
            ]}
            """.trimIndent()
        val preview = ImportFileReader.parseContent("vault.json", json).getOrThrow()
        assertEquals(1, preview.passwords.size)
        assertEquals("john", preview.passwords.first().username)
    }

    @Test
    fun `routes a KeePass XML export to the KeePass parser`() {
        val xml =
            """
            <?xml version="1.0"?>
            <KeePassFile><Root><Group>
              <Entry>
                <String><Key>Title</Key><Value>Example</Value></String>
                <String><Key>UserName</Key><Value>john</Value></String>
                <String><Key>Password</Key><Value>hunter2</Value></String>
                <String><Key>URL</Key><Value>https://example.com</Value></String>
              </Entry>
            </Group></Root></KeePassFile>
            """.trimIndent()
        val preview = ImportFileReader.parseContent("db.xml", xml).getOrThrow()
        assertEquals(1, preview.passwords.size)
        assertEquals("https://example.com", preview.passwords.first().website)
    }

    @Test
    fun `still routes a plain CSV to the CSV parser`() {
        val csv = "url,username,password\nhttps://example.com,john,hunter2\n"
        val preview = ImportFileReader.parseContent("passwords.csv", csv).getOrThrow()
        assertEquals(1, preview.passwords.size)
        assertEquals("hunter2", preview.passwords.first().password)
    }

    @Test
    fun `a CSV whose field contains the KeePass marker still parses as CSV`() {
        val csv = "url,username,password,notes\nhttps://x.com,john,hunter2,\"see <KeePassFile> note\"\n"
        val preview = ImportFileReader.parseContent("passwords.csv", csv).getOrThrow()
        assertEquals(1, preview.passwords.size)
        assertEquals("john", preview.passwords.first().username)
    }

    @Test
    fun `an unrecognised file fails with a clear error`() {
        val result = ImportFileReader.parseContent("mystery.txt", "just some prose, nothing structured")
        assertTrue(result.isFailure)
    }
}
