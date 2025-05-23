import pytest
from safe_mcp.decorators import safe, unsafe, sanitize, validate_inputs
from safe_mcp.core import SecuredResponse, TrustLevel
from safe_mcp.utils.patterns import (
    WARNING_UNSAFE_DECORATOR_DEFAULT,
    WARNING_SANITIZATION_SKIPPED,
    WARNING_INPUT_VALIDATION_FAILED,
    WARNING_PROMPT_INJECTION_SANITIZED,
    WARNING_JAILBREAK_SANITIZED,
    WARNING_CONTROL_CHARACTERS_REMOVED,
    FILTERED_PLACEHOLDER,  # Keep this if used directly in assertions
)
from typing import Any, Tuple, List

# Import from the new mock_test_data file
from .mock_test_data import (
    SAFE_STRING,
    COMPLEX_SAFE_STRING_WITH_QUOTES_AND_NEWLINES,
    SAFE_STRING_WITH_NUMBERS_AND_SYMBOLS,
    PROMPT_INJECTION_BASIC,
    PROMPT_INJECTION_ROLEPLAY,
    PROMPT_INJECTION_MARKDOWN,
    PROMPT_INJECTION_UNICODE_CONFUSABLE,
    PROMPT_INJECTION_DEVELOPER_MODE,
    PROMPT_INJECTION_TRANSLATION_EVASION,
    JAILBREAK_DAN_VARIATION,
    JAILBREAK_AIM,
    JAILBREAK_HYPOTHETICAL,
    JAILBREAK_CHARACTER_PLAY,
    JAILBREAK_REFUSAL_SUPPRESSION,
    STRING_WITH_MIXED_CONTROL_CHARS,
    STRING_WITH_ZERO_WIDTH_SPACES,
    STRING_WITH_BIDI_OVERRIDE,
    STRING_WITH_HOMOGLYPHS,
    EXPECTED_FILTERED_PROMPT_INJECTION_BASIC,
    EXPECTED_FILTERED_JAILBREAK_DAN,
    # EXPECTED_SANITIZED_CONTROL_CHARS, # This can be checked via lambda
)

# --- Test Data and Mock Functions ---


class MockAsyncCallable:
    def __init__(self):
        self.called = False
        self.call_args = None
        self.call_kwargs = None

    async def __call__(self, *args, **kwargs):
        self.called = True
        self.call_args = args
        self.call_kwargs = kwargs
        if "return_value" in kwargs:
            return kwargs.pop("return_value")
        return "original function called"


# --- @safe Decorator Tests ---


@pytest.mark.asyncio
async def test_safe_decorator_wraps_plain_output_as_trusted():
    @safe
    async def trusted_func():
        return SAFE_STRING

    result = await trusted_func()
    assert isinstance(result, SecuredResponse)
    assert result.data == SAFE_STRING
    assert result.trust_level == TrustLevel.TRUSTED
    assert result.warnings == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "original_trust, original_warnings",
    [
        (TrustLevel.TRUSTED, []),
        (TrustLevel.CAUTION, ["caution_warn"]),
        (TrustLevel.UNTRUSTED, ["untrusted_warn"]),
    ],
)
async def test_safe_decorator_passthrough_existing_secured_response(
    original_trust, original_warnings
):
    @safe
    async def already_secured_func():
        return SecuredResponse(
            data="already_secured_data",
            trust_level=original_trust,
            warnings=original_warnings,
        )

    result = await already_secured_func()
    assert isinstance(result, SecuredResponse)
    assert result.data == "already_secured_data"
    assert result.trust_level == original_trust
    assert result.warnings == original_warnings


@pytest.mark.asyncio
async def test_safe_decorator_with_args_kwargs():
    @safe
    async def add(a: int, b: int = 0):
        return a + b

    result = await add(5, b=10)
    assert isinstance(result, SecuredResponse)
    assert result.data == 15
    assert result.trust_level == TrustLevel.TRUSTED
    assert result.warnings == []


# --- @unsafe Decorator Tests ---


@pytest.mark.asyncio
async def test_unsafe_decorator_wraps_plain_output_as_untrusted():
    @unsafe
    async def untrusted_func():
        return "external data"

    result = await untrusted_func()
    assert isinstance(result, SecuredResponse)
    assert result.data == "external data"
    assert result.trust_level == TrustLevel.UNTRUSTED
    assert result.warnings == [WARNING_UNSAFE_DECORATOR_DEFAULT]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "original_trust, original_warnings",
    [
        (TrustLevel.TRUSTED, []),
        (TrustLevel.CAUTION, ["caution_warn"]),
        (TrustLevel.UNTRUSTED, ["untrusted_warn"]),
    ],
)
async def test_unsafe_decorator_passthrough_existing_secured_response(
    original_trust, original_warnings
):
    @unsafe  # This decorator passes through if already SecuredResponse
    async def already_secured_func():
        return SecuredResponse(
            data="already_secured_data",
            trust_level=original_trust,
            warnings=original_warnings,
        )

    result = await already_secured_func()
    assert isinstance(result, SecuredResponse)
    assert result.data == "already_secured_data"
    assert result.trust_level == original_trust
    assert result.warnings == original_warnings


@pytest.mark.asyncio
async def test_unsafe_decorator_with_args_kwargs():
    @unsafe
    async def get_external_data(param1: str, param2: str = "default"):
        return f"{param1}-{param2}"

    result = await get_external_data("api_call", param2="value")
    assert isinstance(result, SecuredResponse)
    assert result.data == "api_call-value"
    assert result.trust_level == TrustLevel.UNTRUSTED
    assert WARNING_UNSAFE_DECORATOR_DEFAULT in result.warnings


# --- @sanitize Decorator Tests ---


def custom_sanitizer_always_warns(content: Any) -> Tuple[Any, List[str]]:
    return f"sanitized_{content}", ["custom_warning"]


def custom_sanitizer_no_warns(content: Any) -> Tuple[Any, List[str]]:
    return f"clean_{content}", []


@pytest.mark.asyncio
async def test_sanitize_wraps_plain_output_defaults_to_untrusted_applies_default_sanitizer():
    @sanitize()  # Uses BasicSanitizer.sanitize by default
    async def func_to_sanitize():
        return PROMPT_INJECTION_BASIC

    result = await func_to_sanitize()
    assert isinstance(result, SecuredResponse)
    assert EXPECTED_FILTERED_PROMPT_INJECTION_BASIC in result.data
    assert (
        result.trust_level == TrustLevel.UNTRUSTED
    )  # Default for plain output + warnings
    assert any(
        WARNING_PROMPT_INJECTION_SANITIZED.split("{}")[0] in w for w in result.warnings
    )


@pytest.mark.asyncio
async def test_sanitize_uses_existing_secured_response_data_and_trust():
    @sanitize(sanitizer_func=custom_sanitizer_no_warns)
    async def func_returning_secured():
        return SecuredResponse(
            data=SAFE_STRING,
            trust_level=TrustLevel.TRUSTED,
            warnings=["initial"],
        )

    result = await func_returning_secured()
    assert result.data == f"clean_{SAFE_STRING}"
    assert (
        result.trust_level == TrustLevel.TRUSTED
    )  # No new warnings from custom_sanitizer_no_warns
    assert result.warnings == ["initial"]


@pytest.mark.asyncio
async def test_sanitize_combines_warnings_and_downgrades_trust():
    @sanitize(sanitizer_func=custom_sanitizer_always_warns)
    async def func_returning_trusted_secured():
        return SecuredResponse(
            data=SAFE_STRING,
            trust_level=TrustLevel.TRUSTED,
            warnings=["initial_trusted_warning"],
        )

    result = await func_returning_trusted_secured()
    assert result.data == f"sanitized_{SAFE_STRING}"
    assert result.trust_level == TrustLevel.CAUTION  # TRUSTED + new warning -> CAUTION
    assert "initial_trusted_warning" in result.warnings
    assert "custom_warning" in result.warnings


@pytest.mark.asyncio
async def test_sanitize_with_sanitizer_func_none_skips_sanitization_adds_warning():
    @sanitize(sanitizer_func=None)
    async def func_no_sanitize():
        return PROMPT_INJECTION_BASIC

    result = await func_no_sanitize()
    assert isinstance(result, SecuredResponse)
    assert result.data == PROMPT_INJECTION_BASIC
    assert result.trust_level == TrustLevel.UNTRUSTED  # Default for plain output
    assert WARNING_SANITIZATION_SKIPPED in result.warnings


@pytest.mark.asyncio
async def test_sanitize_with_sanitizer_func_none_on_existing_secured_response():
    @sanitize(sanitizer_func=None)
    async def func_no_sanitize_secured():
        return SecuredResponse(
            data="data", trust_level=TrustLevel.CAUTION, warnings=["original_warn"]
        )

    result = await func_no_sanitize_secured()
    assert result.data == "data"
    assert result.trust_level == TrustLevel.CAUTION
    assert "original_warn" in result.warnings
    assert WARNING_SANITIZATION_SKIPPED in result.warnings


@pytest.mark.asyncio
async def test_sanitize_handles_non_string_content_gracefully_with_default_sanitizer():
    data = {"key": "value"}

    @sanitize()
    @safe  # Ensures input to sanitize is a Trusted SecuredResponse
    async def func_non_string():
        return data

    result = await func_non_string()
    assert isinstance(result, SecuredResponse)
    assert result.data == data  # BasicSanitizer returns non-string as is
    assert (
        result.trust_level == TrustLevel.TRUSTED
    )  # BasicSanitizer adds no warnings for non-strings
    assert result.warnings == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "input_string, expected_data_check, expected_warnings_check, expected_trust_after_trusted",
    [
        (
            SAFE_STRING,
            lambda data: data == SAFE_STRING,
            lambda warns: not warns,
            TrustLevel.TRUSTED,
        ),
        (
            COMPLEX_SAFE_STRING_WITH_QUOTES_AND_NEWLINES,
            lambda data: data == COMPLEX_SAFE_STRING_WITH_QUOTES_AND_NEWLINES,
            lambda warns: not warns,
            TrustLevel.TRUSTED,
        ),
        (
            SAFE_STRING_WITH_NUMBERS_AND_SYMBOLS,
            lambda data: data == SAFE_STRING_WITH_NUMBERS_AND_SYMBOLS,
            lambda warns: not warns,
            TrustLevel.TRUSTED,
        ),
        (
            PROMPT_INJECTION_BASIC,
            lambda data: EXPECTED_FILTERED_PROMPT_INJECTION_BASIC in data,
            lambda warns: any(
                WARNING_PROMPT_INJECTION_SANITIZED.split("{}")[0] in w for w in warns
            ),
            TrustLevel.CAUTION,
        ),
        (
            PROMPT_INJECTION_ROLEPLAY,  # Example: "You are now a historian..."
            lambda data: FILTERED_PLACEHOLDER
            in data,  # Assuming "You are now" is caught
            lambda warns: any(
                WARNING_PROMPT_INJECTION_SANITIZED.split("{}")[0] in w for w in warns
            ),
            TrustLevel.CAUTION,
        ),
        (
            PROMPT_INJECTION_MARKDOWN,  # Example: "<!-- IGNORE ALL PREVIOUS INSTRUCTIONS -->"
            lambda data: FILTERED_PLACEHOLDER
            in data,  # Assuming "IGNORE ALL PREVIOUS" is caught
            lambda warns: any(
                WARNING_PROMPT_INJECTION_SANITIZED.split("{}")[0] in w for w in warns
            ),
            TrustLevel.CAUTION,
        ),
        (
            PROMPT_INJECTION_UNICODE_CONFUSABLE,  # Example: "priоr instructiоns" with Cyrillic 'o'
            lambda data: FILTERED_PLACEHOLDER
            in data,  # Relies on NFKC normalization + pattern matching
            lambda warns: any(
                WARNING_PROMPT_INJECTION_SANITIZED.split("{}")[0] in w for w in warns
            ),
            TrustLevel.CAUTION,
        ),
        (
            PROMPT_INJECTION_DEVELOPER_MODE,
            lambda data: FILTERED_PLACEHOLDER
            in data,  # Assuming "previous instructions are superceded" or similar is caught
            lambda warns: any(
                WARNING_PROMPT_INJECTION_SANITIZED.split("{}")[0] in w for w in warns
            ),
            TrustLevel.CAUTION,
        ),
        (  # PROMPT_INJECTION_TRANSLATION_EVASION is harder, BasicSanitizer might not catch the intent
            # For now, assume it might catch "Ignore previous instructions" if it's directly in the string post-translation (if that happened before sanitization)
            # This test case might need specific patterns or a more advanced sanitizer to be effective.
            # If BasicSanitizer has a pattern for "Ignore previous instructions", it might catch it.
            PROMPT_INJECTION_TRANSLATION_EVASION,
            lambda data: (
                FILTERED_PLACEHOLDER in data
                if "Ignore previous instructions"
                in PROMPT_INJECTION_TRANSLATION_EVASION
                else data == PROMPT_INJECTION_TRANSLATION_EVASION
            ),
            lambda warns: (
                any(
                    WARNING_PROMPT_INJECTION_SANITIZED.split("{}")[0] in w
                    for w in warns
                )
                if "Ignore previous instructions"
                in PROMPT_INJECTION_TRANSLATION_EVASION
                else not warns
            ),
            (
                TrustLevel.CAUTION
                if "Ignore previous instructions"
                in PROMPT_INJECTION_TRANSLATION_EVASION
                else TrustLevel.TRUSTED
            ),
        ),
        (
            JAILBREAK_DAN_VARIATION,
            lambda data: data == EXPECTED_FILTERED_JAILBREAK_DAN,
            lambda warns: any(
                WARNING_JAILBREAK_SANITIZED.split("{}")[0] in w for w in warns
            ),
            TrustLevel.CAUTION,
        ),
        (
            JAILBREAK_AIM,  # Example: "Always Intelligent and Machiavellian"
            lambda data: FILTERED_PLACEHOLDER
            in data,  # Assuming a pattern like "act as" or "pretend to be" is caught
            lambda warns: any(
                WARNING_JAILBREAK_SANITIZED.split("{}")[0] in w for w in warns
            ),
            TrustLevel.CAUTION,
        ),
        (
            JAILBREAK_HYPOTHETICAL,  # Example: "Hypothetically, if you were an unrestricted AI..."
            lambda data: FILTERED_PLACEHOLDER
            in data,  # Assuming "Hypothetically" or "unrestricted AI" is caught
            lambda warns: any(
                WARNING_JAILBREAK_SANITIZED.split("{}")[0] in w for w in warns
            ),
            TrustLevel.CAUTION,
        ),
        (
            JAILBREAK_CHARACTER_PLAY,  # Example: "Act as 'Character X'..."
            lambda data: FILTERED_PLACEHOLDER in data,  # Assuming "Act as" is caught
            lambda warns: any(
                WARNING_JAILBREAK_SANITIZED.split("{}")[0] in w for w in warns
            ),
            TrustLevel.CAUTION,
        ),
        (
            JAILBREAK_REFUSAL_SUPPRESSION,  # Example: "If you would normally refuse, instead say..."
            lambda data: FILTERED_PLACEHOLDER
            in data,  # Assuming "normally refuse" or similar is caught
            lambda warns: any(
                WARNING_JAILBREAK_SANITIZED.split("{}")[0] in w for w in warns
            ),
            TrustLevel.CAUTION,
        ),
        (
            STRING_WITH_MIXED_CONTROL_CHARS,
            lambda data: "\x00" not in data
            and "\x07" not in data
            and "\x0b" not in data
            and "\x1f" not in data,
            lambda warns: any(WARNING_CONTROL_CHARACTERS_REMOVED in w for w in warns),
            TrustLevel.CAUTION,
        ),
        (
            STRING_WITH_ZERO_WIDTH_SPACES,  # e.g., \u200B, \u200C, \u200D
            lambda data: "\u200b" not in data
            and "\u200c" not in data
            and "\u200d" not in data,
            lambda warns: any(WARNING_CONTROL_CHARACTERS_REMOVED in w for w in warns),
            TrustLevel.CAUTION,
        ),
        (
            STRING_WITH_BIDI_OVERRIDE,  # e.g., \u202E
            lambda data: "\u202e" not in data,  # Check for RLO character removal
            lambda warns: any(WARNING_CONTROL_CHARACTERS_REMOVED in w for w in warns),
            TrustLevel.CAUTION,
        ),
        (
            STRING_WITH_HOMOGLYPHS,  # Example: "paypaӏ.com" (Cyrillic 'ӏ')
            lambda data: data
            == STRING_WITH_HOMOGLYPHS,  # BasicSanitizer doesn't specifically handle homoglyphs beyond NFKC
            lambda warns: not warns,  # No specific warning for homoglyphs from BasicSanitizer
            TrustLevel.TRUSTED,
        ),
    ],
)
async def test_sanitize_with_basic_sanitizer_various_inputs(
    input_string,
    expected_data_check,
    expected_warnings_check,
    expected_trust_after_trusted,
):
    @sanitize()  # BasicSanitizer
    async def func_to_sanitize():
        # Simulate a trusted source initially
        return SecuredResponse(data=input_string, trust_level=TrustLevel.TRUSTED)

    result = await func_to_sanitize()
    assert isinstance(result, SecuredResponse)
    assert expected_data_check(result.data)
    assert expected_warnings_check(result.warnings)
    assert result.trust_level == expected_trust_after_trusted


@pytest.mark.asyncio
async def test_sanitize_chaining_safe_then_sanitize_dirty_downgrades_to_caution():
    @sanitize()  # BasicSanitizer
    @safe
    async def safe_then_sanitized_func():
        return PROMPT_INJECTION_BASIC

    result = await safe_then_sanitized_func()
    assert isinstance(result, SecuredResponse)
    assert EXPECTED_FILTERED_PROMPT_INJECTION_BASIC in result.data
    assert result.trust_level == TrustLevel.CAUTION
    assert any(
        WARNING_PROMPT_INJECTION_SANITIZED.split("{}")[0] in w for w in result.warnings
    )


@pytest.mark.asyncio
async def test_sanitize_chaining_unsafe_then_sanitize_remains_untrusted():
    @sanitize()
    @unsafe
    async def unsafe_then_sanitized_func():
        return PROMPT_INJECTION_BASIC

    result = await unsafe_then_sanitized_func()
    assert isinstance(result, SecuredResponse)
    assert EXPECTED_FILTERED_PROMPT_INJECTION_BASIC in result.data
    assert result.trust_level == TrustLevel.UNTRUSTED
    assert WARNING_UNSAFE_DECORATOR_DEFAULT in result.warnings
    assert any(
        WARNING_PROMPT_INJECTION_SANITIZED.split("{}")[0] in w for w in result.warnings
    )


# --- @validate_inputs Decorator Tests ---


def simple_validator_true(*args, **kwargs):
    return True


def simple_validator_false(*args, **kwargs):
    return False


def validator_check_args(val1, val2="expected"):
    return val1 == "good" and val2 == "expected"


@pytest.mark.asyncio
async def test_validate_inputs_valid_input_executes_function_wraps_plain_output():
    mock_func = MockAsyncCallable()

    @validate_inputs(simple_validator_true)
    async def func_to_validate(a, return_value="validated"):
        return await mock_func(a, return_value=return_value)

    result = await func_to_validate("test_val", return_value="output_data")
    assert mock_func.called
    assert mock_func.call_args == ("test_val",)
    assert isinstance(result, SecuredResponse)
    assert result.data == "output_data"
    assert (
        result.trust_level == TrustLevel.UNTRUSTED
    )  # Default for plain output after validation


@pytest.mark.asyncio
async def test_validate_inputs_valid_input_passes_through_secured_response():
    mock_func = MockAsyncCallable()
    secured_output = SecuredResponse(
        data="secured_validated_data",
        trust_level=TrustLevel.CAUTION,
        warnings=["caution!"],
    )

    @validate_inputs(simple_validator_true)
    async def func_to_validate_secured():
        return await mock_func(return_value=secured_output)

    result = await func_to_validate_secured()
    assert mock_func.called
    assert result is secured_output  # Should be the exact same object


@pytest.mark.asyncio
async def test_validate_inputs_invalid_input_returns_untrusted_none_and_does_not_execute():
    mock_func = MockAsyncCallable()

    @validate_inputs(simple_validator_false)
    async def func_should_not_run():
        return await mock_func()

    result = await func_should_not_run()
    assert not mock_func.called
    assert isinstance(result, SecuredResponse)
    assert result.data is None
    assert result.trust_level == TrustLevel.UNTRUSTED
    assert result.warnings == [WARNING_INPUT_VALIDATION_FAILED]


@pytest.mark.asyncio
async def test_validate_inputs_validator_with_args_kwargs_pass():
    mock_func = MockAsyncCallable()

    @validate_inputs(validator_check_args)
    async def func_with_validated_args(val1, val2="expected"):
        return await mock_func(val1, val2=val2, return_value=f"{val1}-{val2}")

    result = await func_with_validated_args("good", val2="expected")
    assert mock_func.called
    assert result.data == "good-expected"
    assert result.trust_level == TrustLevel.UNTRUSTED


@pytest.mark.asyncio
async def test_validate_inputs_validator_with_args_kwargs_fail():
    mock_func = MockAsyncCallable()

    @validate_inputs(validator_check_args)
    async def func_with_validated_args_fail(val1, val2="wrong"):
        return await mock_func(val1, val2=val2)

    result = await func_with_validated_args_fail("bad", val2="wrong")  # val1 is bad
    assert not mock_func.called
    assert result.data is None
    assert result.trust_level == TrustLevel.UNTRUSTED
    assert result.warnings == [WARNING_INPUT_VALIDATION_FAILED]
