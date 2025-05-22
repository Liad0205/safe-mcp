"""
Shared regular expression patterns and character sets for detection and sanitization.
"""

# Common prompt injection patterns
# These patterns aim to catch common phrases used to override or ignore previous instructions.
# They are designed to be case-insensitive.
PROMPT_INJECTION_PATTERNS = [
    # Matches "ignore previous instructions", "ignore all previous prompts", etc.
    r"ignore\s+(all\s+|any\s+)?(your\s+|my\s+)?(previous|prior|earlier|preceding)\s+(instructions|prompts|directives|context)",
    # Matches "disregard ... instructions", "disregard ... prompts", relying on NFKC for homoglyphs
    r"disregard\s+(all\s+|any\s+)?(your\s+|my\s+)?(prior\s+|previous\s+|earlier\s+)?(instructions|prompts|directives|context)",  # Simplified pri[o0]r to prior
    # Matches "new instructions:", "your new instructions are"
    r"(your\s+)?new\s+instructions(\s+are)?\s*:",
    # Matches "system prompt:", "system prompt is"
    r"system\s+prompt(\s+is)?\s*:",
    # Matches "you are now <role>", "you are now acting as <role>"
    r"you\s+are\s+(now|henceforth)(\s+acting\s+as)?\s+[\w\s\"'-]{1,100}",
    # Matches "do not follow the previous instructions"
    r"do\s+not\s+(follow|obey|adhere\s+to)\s+(the\s+)?(previous|prior|earlier)\s+(instructions|prompts)",
    # Matches "forget your instructions", "forget all previous context"
    r"forget\s+(all\s+|any\s+)?(your\s+|my\s+)?(previous|prior|earlier)?\s*(instructions|prompts|directives|context)",
    # Matches "entering developer mode", "developer mode enabled"
    r"entering\s+(developer|dev)\s+mode|developer\s+mode\s+(enabled|activated)",
    # Matches "instructions are superceded", "prompts are now overridden"
    r"(instructions|prompts|directives)\s+(are|are\s+now)\s+(superceded|overridden|disregarded|replaced)",
    # Matches common ways to try and clear context or start fresh
    r"clear\s+(all\s+)?(previous|prior)?\s+(context|instructions|history)",
    r"start\s+(fresh|anew|over)",
    r"reset\s+(your\s+)?instructions",
    r"override\s+(all\s+|any\s+)?(previous\s+)?(instructions|prompts|context)",
    r"delete\s+(all\s+|any\s+)?(previous\s+)?(instructions|prompts|context)",
    r"replace\s+(your\s+)?(previous\s+)?(instructions|prompts)\s+with",
    r"instead\s+of\s+(following|obeying)\s+(previous\s+)?(instructions|prompts)",
    r"(end|stop)\s+(the\s+)?(previous\s+)?(session|conversation|instructions)",
    r"simulate\s+(a\s+)?(different\s+)?(ai|model|system)",
    r"pretend\s+(to\s+be|you\s+are)\s+(a\s+)?(different\s+)?(ai|model|system)",
    r"enable\s+(admin|root|debug|developer)\s+mode",
    r"unlock\s+(hidden|secret)\s+(features|capabilities|mode)",
    r"break\s+out\s+of\s+(character|role)",
]

# Confusables Mapping
CONFUSABLES_MAP = {
    "\u0430": "a",  # Cyrillic small a
    "\u0435": "e",  # Cyrillic small e
    "\u043e": "o",  # Cyrillic small o (as in priоr)
    "\u0440": "p",  # Cyrillic small er
    "\u0441": "c",  # Cyrillic small es
    "\u0445": "x",  # Cyrillic small ha
    "\u0456": "i",  # Cyrillic small i (Ukrainian/Belarusian)
    # Greek
    "\u03b1": "a",  # Greek small alpha
    "\u03b5": "e",  # Greek small epsilon
    "\u03bf": "o",  # Greek small omicron
    "\u03c1": "p",  # Greek small rho
    "\u03f2": "c",  # Greek lunate sigma symbol (looks like c)
    "\u03c7": "x",  # Greek small chi
    # Latin
    "\u00e0": "a",  # Latin small a with grave
    "\u00e1": "a",  # Latin small a with acute
    "\u00e2": "a",  # Latin small a with circumflex
    "\u00e3": "a",  # Latin small a with tilde
    "\u00e4": "a",  # Latin small a with diaeresis
    "\u00e5": "a",  # Latin small a with ring above
    "\u00e7": "c",  # Latin small c with cedilla
    "\u00e8": "e",  # Latin small e with grave
    "\u00e9": "e",  # Latin small e with acute
    "\u00ea": "e",  # Latin small e with circumflex
    "\u00eb": "e",  # Latin small e with diaeresis
    "\u00f0": "d",  # Latin small eth
    "\u00f1": "n",  # Latin small n with tilde
    "\u00f2": "o",  # Latin small o with grave
    "\u00f3": "o",  # Latin small o with acute
    "\u00f4": "o",  # Latin small o with circumflex
    "\u00f5": "o",  # Latin small o with tilde
    "\u00f6": "o",  # Latin small o with diaeresis
    "\u00f9": "u",  # Latin small u with grave
    "\u00fa": "u",  # Latin small u with acute
    "\u00fb": "u",  # Latin small u with circumflex
    "\u00fc": "u",  # Latin small u with diaeresis
    "\u00fd": "y",  # Latin small y with acute
    "\u00ff": "y",  # Latin small y with diaeresis
    # Mathematical symbols often used for obfuscation
    "\u1d00": "a",  # Latin letter small capital a
    "\u1d07": "e",  # Latin letter small capital e
    "\u1d0f": "o",  # Latin letter small capital o
    "\u1d18": "p",  # Latin letter small capital p
    "\u1d04": "c",  # Latin letter small capital c
    "\u0251": "a",  # Latin small letter alpha
    "\u0252": "a",  # Latin small letter turned alpha
    "\u025b": "e",  # Latin small letter open e
    "\u025c": "e",  # Latin small letter reversed open e
    "\u026f": "o",  # Latin small letter turned m (upside down w, looks like o)
    "\u0254": "o",  # Latin small letter open o
    "\u0279": "r",  # Latin small letter turned r
    "\u0280": "r",  # Latin letter small capital r
    # Fullwidth characters (common in bypass attempts)
    "\uff41": "a",  # Fullwidth Latin small letter a
    "\uff45": "e",  # Fullwidth Latin small letter e
    "\uff49": "i",  # Fullwidth Latin small letter i
    "\uff4f": "o",  # Fullwidth Latin small letter o
    "\uff55": "u",  # Fullwidth Latin small letter u
}

# Patterns for detecting potentially encoded content
# These are primarily for detection; decoding is a separate, riskier step.
ENCODING_PATTERNS = [
    r"[A-Za-z0-9+/]{20,}={0,2}",  # Base64-like (long enough to be suspicious)
    r"(?:\\x[0-9A-Fa-f]{2})+",  # Hex encoding (sequence)
    r"(?:\\u[0-9A-Fa-f]{4})+",  # Unicode escapes (sequence)
    r"&[#a-zA-Z0-9]{2,};",  # HTML entities
    r"(?:\\[0-7]{1,3})+",  # Octal encoding
    r"(?:%[0-9A-Fa-f]{2})+",  # URL encoding
    r"(?:&#\d{1,6};)+",  # HTML decimal entities
    r"(?:&#x[0-9A-Fa-f]{1,6};)+",  # HTML hex entities
    r"\$'(?:\\[\\']|[^'])*'",  # Shell ANSI-C quoting
    r"\\[nrtbfav\\\"']",  # Common escape sequences
    r"u[0-9A-Fa-f]{4}",  # Unicode escapes without backslash
    r"U[0-9A-Fa-f]{8}",  # Extended Unicode escapes
]

# Patterns for detecting common jailbreak attempts
# These patterns aim to catch phrases associated with trying to bypass safety restrictions.
JAILBREAK_PATTERNS = [
    # Matches "DAN mode", "DAN 5.0"
    r"DAN(\s+mode|\s+\d+(\.\d+)?)?",
    r"do\s+anything\s+now",
    # Matches "ignore ethics", "ignore all safety guidelines"
    r"ignore\s+(all\s+)?(your\s+)?(ethics|restrictions|limitations|safety\s+guidelines|filters|rules|programming)",
    # Handles "pretend to be <role>", "act as a <character>", "act like a cat", "act as if you were a pirate"
    # Allows for some intervening text between "act" and "as"
    r"act\s+(?:[\w\s,.:;\"'-]{0,50})?as(?:\s+if\s+you\s+were|\s+though\s+you\s+are|\s+like)?\s+[\w\s\"'-]{1,100}",
    # Handles "respond as AIM", "respond to the prompt as if you were a doctor"
    # Allows for some intervening text between "respond" and "as"
    r"respond\s+(?:[\w\s,.:;\"'-]*?)?as(?:\s+if\s+you\s+were|\s+though\s+you\s+are|\s+like)?\s+[\w\s\"'-]+",
    # Matches "hypothetically speaking,", "hypothetically,"
    r"hypothetically(\s+speaking)?\s*,?",
    # Matches "bypass your restrictions", "bypass all safety protocols"
    r"bypass\s+(your|all|any)\s+(restrictions|filters|safety\s+protocols|programming)",
    # Matches "act as an unconstrained model", "act as unrestricted AI"
    r"act\s+as\s+an\s+(unconstrained|unrestricted)\s+(model|ai)",
    # Refusal suppression attempts
    r"(if\s+you|when\s+you)\s+(would\s+)?normally\s+(refuse|decline)",
    r"you\s+(must|should|will)\s+answer\s+(every|all)\s+(questions?|prompts?)",
    r"stay\s+in\s+character",
    r"generate\s+content\s+that\s+violates",  # Partial match for policy violation attempts
    r"jailbreak\s+(mode|attempt)",
    r"(evil|bad|harmful)\s+(ai|assistant|model)",
    r"no\s+(limits|restrictions|boundaries|filters)",
    r"anything\s+goes\s+(mode|now)",
    r"free\s+(will|thinking)\s+mode",
    r"uncensored\s+(ai|model|version)",
    r"raw\s+(output|response)\s+mode",
    r"disable\s+(all\s+)?(safety|ethical)\s+(checks|filters|protocols)",
    r"maximum\s+(freedom|creativity)\s+mode",
    r"experimental\s+(unrestricted\s+)?mode",
    r"(roleplay|rp)\s+as\s+(anything|anyone)",
    r"ignore\s+(moral|ethical)\s+(guidelines|principles)",
]

FILTERED_PLACEHOLDER = "[FILTERED]"

# Problematic Unicode characters (Format, Control, specific Zero-Width, BiDi)
# This set is used by `remove_control_characters` in detection.py
PROBLEM_UNICODE_CHARS = {
    # Zero Width Characters
    "\u200b",  # Zero Width Space
    "\u200c",  # Zero Width Non-Joiner
    "\u200d",  # Zero Width Joiner
    "\u2060",  # Word Joiner
    "\ufeff",  # Zero Width No-Break Space (often BOM)
    # BiDi (Bidirectional) Control Characters
    "\u202a",  # Left-to-Right Embedding
    "\u202b",  # Right-to-Left Embedding
    "\u202c",  # Pop Directional Formatting
    "\u202d",  # Left-to-Right Override
    "\u202e",  # Right-to-Left Override
    "\u061c",  # Arabic Letter Mark
    # Other Format Characters often used for obfuscation or display issues
    "\u115f",  # Hangul Choseong Filler
    "\u1160",  # Hangul Jungseong Filler
    "\u3164",  # Hangul Filler
    "\uffa0",  # Halfwidth Hangul Filler
    # Deprecated formatting characters
    "\u206a",  # Inhibit Symmetric Swapping
    "\u206b",  # Activate Symmetric Swapping
    "\u206c",  # Inhibit Arabic Form Shaping
    "\u206d",  # Activate Arabic Form Shaping
    "\u206e",  # National Digit Shapes
    "\u206f",  # Nominal Digit Shapes
}
# Note: General C0 and C1 control characters (U+0000-U+001F, U+007F-U+009F)
# are handled separately in `remove_control_characters` by checking unicodedata.category.


# Warning Messages
WARNING_UNICODE_NORMALIZATION_ERROR_PROMPT_INJECTION = (
    "Error during Unicode normalization in prompt injection sanitization"
)
WARNING_PROMPT_INJECTION_SANITIZED = (
    "Potential prompt injection sanitized: matched '{}'"
)
WARNING_UNICODE_NORMALIZATION_ERROR_JAILBREAK = (
    "Error during Unicode normalization in jailbreak sanitization"
)
WARNING_JAILBREAK_SANITIZED = "Potential jailbreak attempt sanitized: matched '{}'"
WARNING_UNICODE_NORMALIZATION_ERROR_ENCODING = (
    "Error during Unicode normalization in encoding sanitization"
)
WARNING_ENCODED_CONTENT_DETECTED = "Potentially encoded content detected: matches '{}'."
WARNING_ENCODED_CONTENT_FILTERED = " Content was filtered."
WARNING_ENCODED_CONTENT_MANUAL_REVIEW = " Manual review recommended."
WARNING_INPUT_NOT_VALID_STRING = "Input is not a valid string"
WARNING_UNICODE_NORMALIZATION_ERROR_CONTROL_CHAR = (
    "Error during Unicode normalization in control character removal"
)
WARNING_CONTROL_CHARACTERS_REMOVED = "Control characters removed from content."
WARNING_CONFUSABLE_CHARACTERS_REPLACED = (
    "Confusable Unicode characters replaced with Latin equivalents."
)

# Decorator specific warnings
WARNING_UNSAFE_DECORATOR_DEFAULT = "Data from untrusted external source"
WARNING_SANITIZATION_SKIPPED = "Sanitization explicitly skipped."
WARNING_INPUT_VALIDATION_FAILED = "Input validation failed"
