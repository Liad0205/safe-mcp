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
    if prior_trust == TrustLevel.TRUSTED:
        # If the prior trust is trusted, we only downgrade to caution if there are new warnings
        return TrustLevel.TRUSTED if len(new_warnings) == 0 else TrustLevel.CAUTION
    elif prior_trust == TrustLevel.UNTRUSTED:
        # If the prior trust is untrusted, we only upgrade to caution if there are no new warnings
        return TrustLevel.CAUTION if len(new_warnings) == 0 else TrustLevel.UNTRUSTED
    else:
        # If the prior trust is caution, we maintain caution unless there are new warnings
        return TrustLevel.CAUTION if len(new_warnings) == 0 else TrustLevel.UNTRUSTED
