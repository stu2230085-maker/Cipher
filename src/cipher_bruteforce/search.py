from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from typing import Iterable

from .attacks import generate_vigenere_keys_by_frequency, hillclimb_substitution, vigenere_candidates
from .scoring import CompositeScorer, ScoreBreakdown
from .transforms import (
    atbash,
    caesar_decode,
    decode_base64,
    decode_hex,
    printable_ratio,
    rail_fence_decode,
    substitution_decode,
    xor_single_byte,
)

DEFAULT_OPERATIONS = {
    "identity",
    "base64",
    "hex",
    "atbash",
    "caesar",
    "rot13",
    "railfence",
    "xor",
    "vigenere",
    "substitution",
}


@dataclass
class SearchConfig:
    depth: int = 2
    beam_width: int = 80
    top_n: int = 20
    timeout_seconds: float = 5.0
    operations: set[str] = field(default_factory=lambda: set(DEFAULT_OPERATIONS))
    max_rails: int = 12
    xor_key_limit: int = 256
    xor_printable_threshold: float = 0.70
    vigenere_keys: list[str] = field(default_factory=list)
    vigenere_auto_max_key_length: int = 0
    vigenere_auto_top_shifts: int = 2
    vigenere_auto_max_keys: int = 200
    substitution_keys: list[str] = field(default_factory=list)
    substitution_restarts: int = 8
    substitution_iterations: int = 2000
    substitution_top_k: int = 4
    random_seed: int = 1337


@dataclass(frozen=True)
class SearchResult:
    score: float
    chain: tuple[str, ...]
    text: str
    score_breakdown: ScoreBreakdown

    def as_json(self) -> dict:
        return {
            "score": self.score,
            "chain": list(self.chain),
            "text": self.text,
            "score_breakdown": asdict(self.score_breakdown),
        }


def _append_candidate(
    candidates: list[tuple[float, tuple[str, ...], str, ScoreBreakdown]],
    chain: tuple[str, ...],
    text: str,
    scorer: CompositeScorer,
) -> None:
    breakdown = scorer.score(text)
    candidates.append((breakdown.total, chain, text, breakdown))


def _generate_once(text: str, config: SearchConfig, scorer: CompositeScorer) -> Iterable[tuple[str, str]]:
    if "base64" in config.operations:
        decoded = decode_base64(text)
        if decoded and decoded != text:
            yield "base64", decoded

    if "hex" in config.operations:
        decoded = decode_hex(text)
        if decoded and decoded != text:
            yield "hex", decoded

    if "atbash" in config.operations:
        yield "atbash", atbash(text)

    if "caesar" in config.operations or "rot13" in config.operations:
        for shift in range(1, 26):
            decoded = caesar_decode(text, shift)
            if shift == 13 and "rot13" in config.operations:
                yield "rot13", decoded
            elif "caesar" in config.operations:
                yield f"caesar:{shift}", decoded

    if "railfence" in config.operations:
        max_rails = min(config.max_rails, max(2, len(text) - 1))
        for rails in range(2, max_rails + 1):
            yield f"railfence:{rails}", rail_fence_decode(text, rails)

    if "xor" in config.operations:
        for key in range(max(0, min(256, config.xor_key_limit))):
            decoded = xor_single_byte(text, key)
            if printable_ratio(decoded) >= config.xor_printable_threshold:
                yield f"xor:0x{key:02x}", decoded

    if "vigenere" in config.operations:
        keys = list(dict.fromkeys(config.vigenere_keys))
        if config.vigenere_auto_max_key_length > 0:
            keys.extend(
                generate_vigenere_keys_by_frequency(
                    text,
                    max_key_length=config.vigenere_auto_max_key_length,
                    top_shifts_per_column=config.vigenere_auto_top_shifts,
                    max_keys=config.vigenere_auto_max_keys,
                )
            )
        keys = list(dict.fromkeys(keys))
        for candidate in vigenere_candidates(text, keys, scorer):
            yield candidate.operation, candidate.text

    if "substitution" in config.operations:
        for key in config.substitution_keys:
            decoded = substitution_decode(text, key)
            if decoded != text:
                yield f"substitution:key:{key}", decoded
        for candidate in hillclimb_substitution(
            text,
            restarts=config.substitution_restarts,
            iterations=config.substitution_iterations,
            seed=config.random_seed,
            scorer=scorer,
            top_k=config.substitution_top_k,
        ):
            yield candidate.operation, candidate.text


def run_search(ciphertext: str, config: SearchConfig) -> list[SearchResult]:
    scorer = CompositeScorer()
    start = time.monotonic()

    initial_breakdown = scorer.score(ciphertext)
    current = [(initial_breakdown.total, tuple(["identity"]), ciphertext, initial_breakdown)]
    seen = {ciphertext}

    for _depth in range(max(1, config.depth)):
        if time.monotonic() - start >= config.timeout_seconds:
            break

        next_candidates: list[tuple[float, tuple[str, ...], str, ScoreBreakdown]] = []
        for _, chain, text, _ in current:
            for operation, decoded in _generate_once(text, config, scorer):
                if time.monotonic() - start >= config.timeout_seconds:
                    break
                if decoded == text:
                    continue
                key = json.dumps([operation, decoded], ensure_ascii=False)
                if key in seen:
                    continue
                seen.add(key)
                _append_candidate(next_candidates, chain + (operation,), decoded, scorer)

        if not next_candidates:
            break

        next_candidates.sort(key=lambda item: item[0], reverse=True)
        current = next_candidates[: max(1, config.beam_width)]

    results = sorted(current, key=lambda item: item[0], reverse=True)[: max(1, config.top_n)]
    return [
        SearchResult(score=score, chain=chain, text=text, score_breakdown=breakdown)
        for score, chain, text, breakdown in results
    ]
