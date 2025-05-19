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
