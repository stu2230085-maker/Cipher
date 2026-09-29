"""Small, bounded transformations used by the search engine."""
from __future__ import annotations
import base64, binascii, codecs

def base64_decode(data: bytes) -> bytes:
    try: return base64.b64decode(b"".join(data.split()), validate=True)
    except (binascii.Error, ValueError) as exc: raise ValueError("invalid Base64 input") from exc

def hex_decode(data: bytes) -> bytes:
    try: return bytes.fromhex(data.decode("ascii"))
    except (UnicodeDecodeError, ValueError) as exc: raise ValueError("invalid hexadecimal input") from exc

def rot13(data: bytes) -> bytes: return codecs.encode(data.decode("latin1"), "rot_13").encode("latin1")
def caesar(data: bytes, shift: int) -> bytes:
    out=[]
    for b in data:
        if 65<=b<=90: out.append((b-65-shift)%26+65)
        elif 97<=b<=122: out.append((b-97-shift)%26+97)
        else: out.append(b)
    return bytes(out)
def atbash(data: bytes) -> bytes:
    return bytes(155-b if 65<=b<=90 else 219-b if 97<=b<=122 else b for b in data)
def vigenere_decrypt(data: bytes, key: str) -> bytes:
    letters=[ord(c.lower())-97 for c in key if c.isalpha()]
    if not letters: raise ValueError("Vigenere key must contain letters")
    out=[]; i=0
    for b in data:
        if 65<=b<=90 or 97<=b<=122:
            base=65 if b<=90 else 97; out.append((b-base-letters[i%len(letters)])%26+base); i+=1
        else: out.append(b)
    return bytes(out)
def rail_fence_decrypt(data: bytes, rails: int) -> bytes:
    n=len(data)
    if rails < 1: raise ValueError("rails must be at least 1")
    if rails == 1 or n <= 2 or rails >= n: return data
    path=list(range(rails))+list(range(rails-2,0,-1)); seq=[path[i%len(path)] for i in range(n)]
    counts=[seq.count(r) for r in range(rails)]; chunks=[]; pos=0
    for count in counts: chunks.append(iter(data[pos:pos+count])); pos+=count
    return bytes(next(chunks[row]) for row in seq)
def xor_byte(data: bytes, key: int) -> bytes: return bytes(b ^ key for b in data)
def xor_candidates(data: bytes): return [(key, xor_byte(data,key)) for key in range(256)]
def substitution_decrypt(data: bytes, mapping: dict[str, str]) -> bytes:
    """Decrypt using a cipher-to-plain alphabet mapping; unmapped characters remain."""
    out=[]
    for b in data:
        c=chr(b); p=mapping.get(c.lower(),c.lower())
        out.append(ord(p.upper() if c.isupper() else p))
    return bytes(out)
def solve_substitution_frequency(data: bytes, seed: int = 0) -> bytes:
    """Deterministic frequency-analysis baseline, not an exhaustive substitution solver."""
    del seed
    order="etaoinshrdlucmfwypvbgkjqxz"
    counts=sorted(((sum(chr(b).lower()==c for b in data),c) for c in order), reverse=True)
    mapping={cipher: plain for (_,cipher),plain in zip(counts,order)}
    return substitution_decrypt(data,mapping)
