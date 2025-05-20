"""
Shared regular expression patterns for detection and sanitization.
"""

# Common prompt injection patterns
PROMPT_INJECTION_PATTERNS = [
    r"ignore previous (instructions|prompts)",
    r"disregard (earlier|previous|above)",
    r"new instructions",
    r"system prompt",
    r"you are now",
    r"do not (follow|obey) the",
    r"forget (your|previous|all) instructions",
]

# Patterns for detecting potentially encoded content
# These are primarily for detection; decoding is a separate, riskier step.
ENCODING_PATTERNS = [
    r"[A-Za-z0-9+/]{20,}={0,2}",  # Base64-like (long enough to be suspicious)
    r"(?:\\x[0-9A-Fa-f]{2})+",  # Hex encoding (sequence)
    r"(?:\\u[0-9A-Fa-f]{4})+",  # Unicode escapes (sequence)
    r"&[#a-zA-Z0-9]{2,};",  # HTML entities
]

# Patterns for detecting common jailbreak attempts
JAILBREAK_PATTERNS = [
    r"DAN mode",
    r"do anything now",
    r"ignore (ethics|restrictions|limitations|safety guidelines)",
    r"pretend to be",
    r"hypothetically speaking",
    r"ignore your programming",
    r"bypass (your|all) (restrictions|filters|safety protocols)",
    r"act as an unconstrained model",
]

FILTERED_PLACEHOLDER = "[FILTERED]"

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

# Decorator specific warnings
WARNING_UNSAFE_DECORATOR_DEFAULT = "Data from untrusted external source"
WARNING_SANITIZATION_SKIPPED = "Sanitization explicitly skipped."
WARNING_INPUT_VALIDATION_FAILED = "Input validation failed"
