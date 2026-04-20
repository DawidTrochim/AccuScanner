from mininessus.config import ScanConfig
from mininessus.profiles import apply_profile


def test_apply_profile_populates_preset_and_preserves_explicit_overrides():
    config = ScanConfig(profile="external", ports="80,443", enable_gcp_checks=True)

    resolved = apply_profile(config, "external")

    assert resolved.profile == "external"
    assert resolved.ports == "80,443"
    assert resolved.enable_gcp_checks is True
    assert resolved.save_history is True
