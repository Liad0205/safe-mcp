from ..core import TrustLevel


def determine_trust_level(prior_trust: TrustLevel, new_warnings: list) -> TrustLevel:
    """
    Determine the trust level based on prior trust and new warnings.
    This function follows the principle of least trust by only downgrading trust.

    Args:
        prior_trust: The prior trust level
        new_warnings: List of new warnings

    Returns:
        The determined trust level
    """
    if not new_warnings:
        # Maintain prior trust if there are no new warnings
        return prior_trust

    # Downgrade trust level since we saw new warnings
    if prior_trust == TrustLevel.TRUSTED:
        return TrustLevel.CAUTION

    return TrustLevel.UNTRUSTED
