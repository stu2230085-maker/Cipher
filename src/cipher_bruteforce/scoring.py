from __future__ import annotations

import math
import string
from dataclasses import dataclass

ENGLISH_FREQ = {
    "a": 0.08167,
    "b": 0.01492,
    "c": 0.02782,
    "d": 0.04253,
    "e": 0.12702,
    "f": 0.02228,
    "g": 0.02015,
    "h": 0.06094,
    "i": 0.06966,
    "j": 0.00153,
    "k": 0.00772,
    "l": 0.04025,
    "m": 0.02406,
    "n": 0.06749,
    "o": 0.07507,
    "p": 0.01929,
    "q": 0.00095,
    "r": 0.05987,
    "s": 0.06327,
    "t": 0.09056,
    "u": 0.02758,
    "v": 0.00978,
    "w": 0.02360,
    "x": 0.00150,
    "y": 0.01974,
    "z": 0.00074,
}

COMMON_WORDS = (
    "the",
    "and",
    "this",
    "that",
    "hello",
    "secret",
    "flag",
    "cipher",
    "attack",
)

JP_HINT_WORDS = ("です", "ます", "暗号", "秘密", "こんにちは", "の", "に", "を")

TETRAGRAM_WEIGHTS = {
    "TION": 2.7,
    "THER": 2.6,
    "WITH": 2.4,
    "MENT": 2.2,
    "THAT": 2.2,
    "HERE": 2.1,
    "OULD": 1.9,
    "IGHT": 1.8,
    "HAVE": 1.7,
    "IONS": 1.7,
}


@dataclass(frozen=True)
class ScoreBreakdown:
    total: float
    printable: float
    english: float
    japanese: float
    penalty: float


class CompositeScorer:
    """Transparent, testable, pluggable heuristic scorer."""

    def score(self, text: str) -> ScoreBreakdown:
        printable = self._printable_score(text)
        english = self._english_score(text)
        japanese = self._japanese_score(text)
        penalty = self._control_penalty(text)
        total = printable + english + japanese - penalty
        return ScoreBreakdown(
            total=total,
            printable=printable,
            english=english,
            japanese=japanese,
            penalty=penalty,
        )

    def _printable_score(self, text: str) -> float:
        if not text:
            return -1000.0
        printable = 0
        for ch in text:
            cp = ord(ch)
            if (
                ch in string.printable
                or 0x3040 <= cp <= 0x30FF
                or 0x4E00 <= cp <= 0x9FFF
                or 0xFF00 <= cp <= 0xFFEF
            ):
                printable += 1
        return 25.0 * printable / len(text)

    def _english_score(self, text: str) -> float:
        lower = text.lower()
        letters = [ch for ch in lower if "a" <= ch <= "z"]
        if not letters:
            return 0.0

        score = 0.0
        for word in COMMON_WORDS:
            score += 5.0 * lower.count(word)

        sample = "".join(letters)
        for gram, weight in TETRAGRAM_WEIGHTS.items():
            score += weight * sample.count(gram.lower())

        counts = {ch: sample.count(ch) / len(sample) for ch in ENGLISH_FREQ}
        chi_sq = 0.0
        for letter, expected in ENGLISH_FREQ.items():
            observed = counts[letter]
            chi_sq += (observed - expected) ** 2 / max(expected, 1e-9)
        score += max(0.0, 30.0 - chi_sq)

        return score

    def _japanese_score(self, text: str) -> float:
        if not text:
            return 0.0
        jp_chars = 0
        for ch in text:
            cp = ord(ch)
            if 0x3040 <= cp <= 0x30FF or 0x4E00 <= cp <= 0x9FFF:
                jp_chars += 1
        ratio = jp_chars / len(text)

        lower = text.lower()
        hints = sum(lower.count(word) for word in JP_HINT_WORDS)
        return ratio * 20.0 + hints * 2.0

    def _control_penalty(self, text: str) -> float:
        penalty = 0.0
        for ch in text:
            cp = ord(ch)
            if cp < 32 and ch not in "\n\r\t":
                penalty += 4.0
            if math.isnan(cp):
                penalty += 100.0
        return penalty
