"""Beam search with explicit work, depth and time limits."""
from __future__ import annotations
import time
from .models import Candidate
from .operations import base64_decode,hex_decode,rot13,caesar,atbash,rail_fence_decrypt,vigenere_decrypt,xor_candidates
from .scoring import EnglishScorer, UnicodeScorer

def search(data: bytes, *, depth=2, beam_width=20, max_work=1000, timeout=2.0, operations=None, vigenere_keys=()):
    if not 0 <= depth <= 5 or not 1 <= beam_width <= 100 or not 1 <= max_work <= 10000: raise ValueError("unsafe search limit")
    allowed=set(operations or ("base64","hex","rot13","caesar","atbash","rail","xor","vigenere")); scorer=EnglishScorer(); unicode=UnicodeScorer()
    initial=Candidate(data,max(scorer.score(data),unicode.score(data))); beam=[initial]; seen={data}; results=[initial]; work=0; started=time.monotonic()
    for _ in range(depth):
        nxt=[]
        for cand in beam:
            generated=[]
            for name, fn in (("base64",base64_decode),("hex",hex_decode),("rot13",rot13),("atbash",atbash)):
                if name in allowed:
                    try: generated.append((name,fn(cand.data)))
                    except ValueError: pass
            if "caesar" in allowed: generated += [(f"caesar:{i}",caesar(cand.data,i)) for i in range(1,26)]
            if "rail" in allowed: generated += [(f"rail:{i}",rail_fence_decrypt(cand.data,i)) for i in range(2,min(10,len(cand.data)))]
            if "xor" in allowed: generated += [(f"xor:{k}",v) for k,v in xor_candidates(cand.data)]
            if "vigenere" in allowed: generated += [(f"vigenere:{k}",vigenere_decrypt(cand.data,k)) for k in vigenere_keys]
            for name, value in generated:
                work+=1
                if work>max_work or time.monotonic()-started>timeout: break
                if value in seen: continue
                seen.add(value); nxt.append(Candidate(value,max(scorer.score(value),unicode.score(value)),cand.history+(name,)))
            if work>max_work or time.monotonic()-started>timeout: break
        results.extend(nxt); beam=sorted(nxt,key=lambda c:c.score,reverse=True)[:beam_width]
        if not beam or work>max_work or time.monotonic()-started>timeout: break
    return sorted(results,key=lambda c:c.score,reverse=True)
