from __future__ import annotations

import itertools
import random
import string
from collections import Counter
from dataclasses import dataclass

from .scoring import CompositeScorer
from .transforms import vigenere_decode

ENGLISH_ORDER = "ETAOINSHRDLCUMWFGYPBVKJXQZ"


@dataclass(frozen=True)
class AttackCandidate:
    operation: str
    text: str
    score: float


def _letters_only(text: str) -> str:
    return "".join(ch for ch in text.upper() if "A" <= ch <= "Z")


def _initial_substitution_key(ciphertext: str) -> str:
    counts = Counter(_letters_only(ciphertext))
    by_freq = [pair[0] for pair in counts.most_common()]
    remaining = [ch for ch in string.ascii_uppercase if ch not in by_freq]
    cipher_order = by_freq + remaining

    mapping = {}
    for i, c in enumerate(cipher_order):
        mapping[c] = ENGLISH_ORDER[i]
    key = "".join(mapping[ch] for ch in string.ascii_uppercase)
    return key


def _decode_with_plain_mapping(text: str, mapping: dict[str, str]) -> str:
    out: list[str] = []
    for ch in text:
        up = ch.upper()
        if up in mapping:
            p = mapping[up]
            out.append(p if ch.isupper() else p.lower())
        else:
            out.append(ch)
    return "".join(out)


def hillclimb_substitution(
    ciphertext: str,
    restarts: int,
    iterations: int,
    seed: int,
    scorer: CompositeScorer,
    top_k: int = 5,
) -> list[AttackCandidate]:
    letters = _letters_only(ciphertext)
    if len(letters) < 20:
        return []

    rng = random.Random(seed)
    base_key = _initial_substitution_key(ciphertext)

    winners: list[AttackCandidate] = []
    for restart in range(max(1, restarts)):
        key_list = list(base_key)
        rng.shuffle(key_list)

        best_key = key_list[:]
        best_score = float("-inf")

        for _ in range(max(1, iterations)):
            i, j = rng.sample(range(26), 2)
            key_list[i], key_list[j] = key_list[j], key_list[i]

            mapping = {chr(ord("A") + idx): key_list[idx] for idx in range(26)}
            decoded = _decode_with_plain_mapping(ciphertext, mapping)
            score = scorer.score(decoded).total

            if score > best_score:
                best_score = score
                best_key = key_list[:]
            else:
                key_list[i], key_list[j] = key_list[j], key_list[i]

        best_map = {chr(ord("A") + idx): best_key[idx] for idx in range(26)}
        best_text = _decode_with_plain_mapping(ciphertext, best_map)
        winners.append(
            AttackCandidate(
                operation=f"substitution-hillclimb-r{restart + 1}",
                text=best_text,
                score=scorer.score(best_text).total,
            )
        )

    winners.sort(key=lambda item: item.score, reverse=True)
    unique: list[AttackCandidate] = []
    seen = set()
    for item in winners:
        if item.text in seen:
            continue
        unique.append(item)
        seen.add(item.text)
        if len(unique) >= top_k:
            break
    return unique


def _caesar_chi_square(column: str, shift: int) -> float:
    decoded = "".join(chr((ord(ch) - ord("A") - shift) % 26 + ord("A")) for ch in column)
    counts = Counter(decoded)
    n = len(decoded)
    total = 0.0
    for letter, expected in {
        "A": 0.08167,
        "B": 0.01492,
        "C": 0.02782,
        "D": 0.04253,
        "E": 0.12702,
        "F": 0.02228,
        "G": 0.02015,
        "H": 0.06094,
        "I": 0.06966,
        "J": 0.00153,
        "K": 0.00772,
        "L": 0.04025,
        "M": 0.02406,
        "N": 0.06749,
        "O": 0.07507,
        "P": 0.01929,
        "Q": 0.00095,
        "R": 0.05987,
        "S": 0.06327,
        "T": 0.09056,
        "U": 0.02758,
        "V": 0.00978,
        "W": 0.02360,
        "X": 0.00150,
        "Y": 0.01974,
        "Z": 0.00074,
    }.items():
        observed = counts.get(letter, 0) / max(n, 1)
        total += (observed - expected) ** 2 / max(expected, 1e-9)
    return total


def generate_vigenere_keys_by_frequency(
    ciphertext: str,
    max_key_length: int,
    top_shifts_per_column: int,
    max_keys: int,
) -> list[str]:
    letters = _letters_only(ciphertext)
    if not letters:
        return []

    candidates: list[str] = []
    for key_len in range(1, max(1, max_key_length) + 1):
        columns = [letters[idx::key_len] for idx in range(key_len)]
        shift_options = []
        for column in columns:
            ranked = sorted(range(26), key=lambda s: _caesar_chi_square(column, s))
            shift_options.append(ranked[: max(1, top_shifts_per_column)])

        for shifts in itertools.product(*shift_options):
            key = "".join(chr(ord("A") + shift) for shift in shifts)
            candidates.append(key)
            if len(candidates) >= max_keys:
                return candidates
    return candidates


def vigenere_candidates(
    ciphertext: str,
    keys: list[str],
    scorer: CompositeScorer,
) -> list[AttackCandidate]:
    out = []
    for key in keys:
        text = vigenere_decode(ciphertext, key)
        out.append(
            AttackCandidate(operation=f"vigenere:{key}", text=text, score=scorer.score(text).total)
        )
    out.sort(key=lambda item: item.score, reverse=True)
    return out
