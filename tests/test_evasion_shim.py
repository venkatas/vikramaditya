"""Regression test: evasion.py is a thin shim over sneaky_bits.py (single
source of truth), not a divergent byte-identical copy.

Guards against the drift hazard where a payload-correctness fix to one copy
would silently miss the other. Uses SYNTHETIC data only.
"""
import importlib

import evasion
import sneaky_bits


PUBLIC_API = [
    "sneaky_encode",
    "sneaky_decode",
    "variant_encode",
    "tag_encode",
    "wrap_payload",
    "generate_injection_payloads",
    "main",
]


def test_public_api_is_the_same_object_as_sneaky_bits():
    """Every public symbol on evasion must BE the sneaky_bits object,
    proving there is exactly one implementation (no duplicated logic)."""
    for name in PUBLIC_API:
        assert hasattr(evasion, name), f"evasion missing {name}"
        assert getattr(evasion, name) is getattr(sneaky_bits, name), (
            f"evasion.{name} is a divergent copy, not the sneaky_bits object"
        )


def test_evasion_source_does_not_duplicate_encoder_body():
    """The shim must delegate, not re-implement. The verbatim copy defined
    its own encoder; the shim must not."""
    src = importlib.util.find_spec("evasion").origin
    with open(src, "r", encoding="utf-8") as fh:
        text = fh.read()
    assert "from sneaky_bits import" in text or "import sneaky_bits" in text
    # The original duplicate contained the full function definition body.
    assert "def sneaky_encode(" not in text, (
        "evasion.py re-defines sneaky_encode; it should import it"
    )


def test_roundtrip_equivalence_with_synthetic_data():
    sample = "acme test 127.0.0.1 <payload>"
    assert evasion.sneaky_decode(evasion.sneaky_encode(sample)) == sample
    # Identical result to the canonical module.
    assert evasion.sneaky_encode(sample) == sneaky_bits.sneaky_encode(sample)
