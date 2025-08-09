from __future__ import annotations

"""Pre-compiled regular expression patterns for detection."""

import re
from typing import List

from .patterns import (
    PROMPT_INJECTION_PATTERNS,
    JAILBREAK_PATTERNS,
    ENCODING_PATTERNS,
)


def _compile(patterns: List[str], *, ignore_case: bool = True) -> List[re.Pattern[str]]:
    flags = re.IGNORECASE if ignore_case else 0
    return [re.compile(p, flags) for p in patterns]


COMPILED_PROMPT_INJECTION_PATTERNS = _compile(PROMPT_INJECTION_PATTERNS)
COMPILED_JAILBREAK_PATTERNS = _compile(JAILBREAK_PATTERNS)
# Encoding patterns are not strictly case-insensitive, but compiling with IGNORECASE is safe
COMPILED_ENCODING_PATTERNS = _compile(ENCODING_PATTERNS, ignore_case=False)
