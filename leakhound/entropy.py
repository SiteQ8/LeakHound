"""Shannon entropy, used to spot random looking strings."""
from __future__ import annotations

import math
from collections import Counter


def shannon_entropy(data: str) -> float:
    """Return the Shannon entropy of a string in bits per character.

    A value near 0 means very repetitive text. Random looking tokens such as
    API keys usually sit above 4 bits per character.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())
