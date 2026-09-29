from __future__ import annotations

import base64
import binascii
import string
from collections import Counter
from dataclasses import dataclass


def safe_decode_bytes(data: bytes) -> str:
    for encoding in ("utf-8", "utf-16", "utf-32", "cp932"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    return data.decode("latin-1", errors="replace")


def decode_base64(text: str) -> str | None:
    compact = "".join(text.split())
    if len(compact) < 4:
        return None
    pad = (-len(compact)) % 4
    if pad:
        compact += "=" * pad
    try:
        data = base64.b64decode(compact, validate=True)
    except (binascii.Error, ValueError):
        return None
    return safe_decode_bytes(data)


def decode_hex(text: str) -> str | None:
    compact = "".join(text.split())
    if len(compact) < 2 or len(compact) % 2 != 0:
        return None
    try:
        return safe_decode_bytes(bytes.fromhex(compact))
    except ValueError:
        return None


def caesar_decode(text: str, shift: int) -> str:
    out: list[str] = []
    for char in text:
        if "a" <= char <= "z":
            out.append(chr((ord(char) - ord("a") - shift) % 26 + ord("a")))
        elif "A" <= char <= "Z":
            out.append(chr((ord(char) - ord("A") - shift) % 26 + ord("A")))
        else:
            out.append(char)
    return "".join(out)


def atbash(text: str) -> str:
    out: list[str] = []
    for char in text:
        if "a" <= char <= "z":
            out.append(chr(ord("z") - (ord(char) - ord("a"))))
        elif "A" <= char <= "Z":
            out.append(chr(ord("Z") - (ord(char) - ord("A"))))
        else:
            out.append(char)
    return "".join(out)


def rail_fence_decode(ciphertext: str, rails: int) -> str:
    if rails <= 1 or rails >= len(ciphertext):
        return ciphertext

    pattern = list(range(rails)) + list(range(rails - 2, 0, -1))
    rail_indices = [pattern[i % len(pattern)] for i in range(len(ciphertext))]
    counts = Counter(rail_indices)

    chunks: list[list[str]] = []
    index = 0
    for rail in range(rails):
        count = counts[rail]
        chunks.append(list(ciphertext[index : index + count]))
        index += count

    positions = [0] * rails
    decoded: list[str] = []
    for rail in rail_indices:
        decoded.append(chunks[rail][positions[rail]])
        positions[rail] += 1
    return "".join(decoded)


def vigenere_decode(text: str, key: str) -> str:
    normalized_key = "".join(ch for ch in key.upper() if ch.isalpha())
    if not normalized_key:
        return text

    out: list[str] = []
    index = 0
    for char in text:
        if char.isascii() and char.isalpha():
            base = ord("A") if char.isupper() else ord("a")
            shift = ord(normalized_key[index % len(normalized_key)]) - ord("A")
            out.append(chr((ord(char) - base - shift) % 26 + base))
            index += 1
        else:
            out.append(char)
    return "".join(out)


def substitution_decode(text: str, cipher_alphabet: str) -> str:
    alphabet = string.ascii_uppercase
    key = cipher_alphabet.upper()
    if len(key) != 26 or set(key) != set(alphabet):
        return text
    inverse = {key[i]: alphabet[i] for i in range(26)}

    out: list[str] = []
    for ch in text:
        upper = ch.upper()
        if upper in inverse:
            plain = inverse[upper]
            out.append(plain if ch.isupper() else plain.lower())
        else:
            out.append(ch)
    return "".join(out)


@dataclass(frozen=True)
class XorResult:
    key: int
    text: str


def xor_single_byte(text: str, key: int) -> str:
    raw = text.encode("utf-8", errors="surrogatepass")
    decoded = bytes(byte ^ key for byte in raw)
    return safe_decode_bytes(decoded)


def printable_ratio(text: str) -> float:
    if not text:
        return 0.0
    printable = 0
    for ch in text:
        codepoint = ord(ch)
        if ch in string.printable or 0x3000 <= codepoint <= 0x30FF or 0x4E00 <= codepoint <= 0x9FFF:
            printable += 1
    return printable / len(text)
