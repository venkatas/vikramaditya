"""VAPT anonymization toolkit — strip sensitive pentest data before LLM calls.

Design inspired by zeroc00I/LLM-anonymization (README-only design spec,
https://github.com/zeroc00I/LLM-anonymization). Original spec by zeroc00I;
this is an independent implementation built from the public description.
"""

from .anonymizer import Anonymizer
from .regex_detector import RegexDetector, Detection
from .surrogates import SurrogateGenerator
from .vault import Vault

__all__ = ["Anonymizer", "RegexDetector", "Detection", "SurrogateGenerator", "Vault"]
