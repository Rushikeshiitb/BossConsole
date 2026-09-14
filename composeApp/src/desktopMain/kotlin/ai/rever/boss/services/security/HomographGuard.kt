package ai.rever.boss.services.security

/**
 * Flags lookalike (homograph) domains before a saved credential is autofilled -
 * the exact phishing class a password manager is supposed to defend against.
 *
 * `аpple.com` (with a Cyrillic а) and `xn--80ak6aa92e.com` are different domains
 * from `apple.com` that render almost identically, so a user cannot see the
 * difference and a naive host match would hand the real password to the fake site.
 * This is the detection half; the browser/secret integration calls it and decides
 * whether to warn or withhold.
 *
 * Three signals, each a real attack shape:
 *
 * - **Mixed script in one label** - `аpple` is Cyrillic `а` plus Latin `pple`.
 *   No legitimate label mixes scripts, so this is the strongest signal.
 * - **Whole-script confusable** - a label that is entirely one non-Latin script
 *   where *every* letter has a Latin lookalike (`аррӏе`, all Cyrillic). A real
 *   IDN like `яндекс` is not flagged, because not all of its letters are Latin
 *   lookalikes - which is what keeps this from crying wolf on legitimate IDNs.
 * - **Punycode** - a raw `xn--` label the browser chose not to render as Unicode.
 *   Advisory: legitimate, but worth a second look before autofilling.
 *
 * Pure and total, so every case is a plain unit test.
 */
object HomographGuard {
    enum class Reason {
        MIXED_SCRIPT,
        WHOLE_SCRIPT_CONFUSABLE,
        PUNYCODE,
    }

    data class Verdict(
        val host: String,
        val suspicious: Boolean,
        val reasons: List<Reason>,
    )

    /** Codepoints of non-Latin letters that closely resemble a Latin letter. */
    private val CONFUSABLE_CODEPOINTS: Set<Int> =
        setOf(
            // Cyrillic: а е о р с у х ѕ і ј ӏ һ ԁ
            0x0430,
            0x0435,
            0x043E,
            0x0440,
            0x0441,
            0x0443,
            0x0445,
            0x0455,
            0x0456,
            0x0458,
            0x04CF,
            0x04BB,
            0x0501,
            // Greek: ο α ε ρ ν
            0x03BF,
            0x03B1,
            0x03B5,
            0x03C1,
            0x03BD,
        )

    private const val PUNYCODE_PREFIX = "xn--"

    /** Analyse [host] label by label. */
    fun analyze(host: String): Verdict {
        val reasons = LinkedHashSet<Reason>()
        for (label in host.trim().lowercase().split('.')) {
            if (label.isNotEmpty()) classifyLabel(label, reasons)
        }
        return Verdict(host, reasons.isNotEmpty(), reasons.toList())
    }

    /** Convenience: just the boolean. */
    fun isSuspicious(host: String): Boolean = analyze(host).suspicious

    private fun classifyLabel(
        label: String,
        reasons: MutableSet<Reason>,
    ) {
        if (label.startsWith(PUNYCODE_PREFIX)) reasons.add(Reason.PUNYCODE)

        val scripts = HashSet<Character.UnicodeScript>()
        var letters = 0
        var latin = 0
        var confusable = 0

        var i = 0
        while (i < label.length) {
            val cp = label.codePointAt(i)
            i += Character.charCount(cp)
            if (!Character.isLetter(cp)) continue

            letters++
            val script = Character.UnicodeScript.of(cp)
            if (script != Character.UnicodeScript.COMMON && script != Character.UnicodeScript.INHERITED) {
                scripts.add(script)
            }
            if (script == Character.UnicodeScript.LATIN) latin++
            if (cp in CONFUSABLE_CODEPOINTS) confusable++
        }

        if (scripts.size > 1) reasons.add(Reason.MIXED_SCRIPT)
        // Entirely non-Latin, and every letter is a Latin lookalike: a pure spoof.
        if (letters > 0 && latin == 0 && confusable == letters) reasons.add(Reason.WHOLE_SCRIPT_CONFUSABLE)
    }
}
