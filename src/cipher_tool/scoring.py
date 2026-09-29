"""Transparent ranking signals; scores are not proof of plaintext."""
from __future__ import annotations
class EnglishScorer:
    words=(b" the ",b" and ",b" to ",b" of ",b" is ",b"this",b"that",b"hello")
    def score(self, data: bytes) -> float:
        if not data: return -10.0
        printable=sum(32<=b<127 or b in (9,10,13) for b in data)/len(data)
        lower=b" "+data.lower()+b" "
        common=sum(lower.count(w) for w in self.words)
        letters=sum((65<=b<=90) or (97<=b<=122) for b in data)/len(data)
        return printable*12 + letters*3 + common*8
class UnicodeScorer:
    def score(self, data: bytes) -> float:
        try: text=data.decode("utf-8")
        except UnicodeDecodeError: return -8.0
        return sum(c.isprintable() or c.isspace() for c in text)/max(1,len(text))*10
