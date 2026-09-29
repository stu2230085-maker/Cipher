from __future__ import annotations
import argparse,json,sys
from .search import search

def main(argv=None):
 p=argparse.ArgumentParser(description="Bounded heuristic cipher candidate generator")
 source=p.add_mutually_exclusive_group(); source.add_argument("input",nargs="?"); source.add_argument("--file"); source.add_argument("--stdin",action="store_true")
 p.add_argument("--depth",type=int,default=2); p.add_argument("--beam-width",type=int,default=20); p.add_argument("--top",type=int,default=10); p.add_argument("--max-work",type=int,default=1000); p.add_argument("--timeout",type=float,default=2); p.add_argument("--operations",default="base64,hex,rot13,caesar,atbash,rail,xor,vigenere"); p.add_argument("--vigenere-key",action="append",default=[]); p.add_argument("--key-file"); p.add_argument("--seed",type=int,default=0); p.add_argument("--json",action="store_true")
 a=p.parse_args(argv)
 try:
  if a.file: data=open(a.file,"rb").read()
  elif a.stdin: data=sys.stdin.buffer.read()
  elif a.input is not None: data=a.input.encode()
  else: p.error("provide input, --file, or --stdin")
  keys=a.vigenere_key + (open(a.key_file,encoding="utf8").read().splitlines() if a.key_file else [])
  results=search(data,depth=a.depth,beam_width=a.beam_width,max_work=a.max_work,timeout=a.timeout,operations=[x for x in a.operations.split(',') if x],vigenere_keys=keys)[:a.top]
  payload=[{"text":x.text(),"score":x.score,"history":list(x.history)} for x in results]
  if a.json: print(json.dumps(payload,ensure_ascii=False))
  else:
   for x in payload: print(f"[{x['score']:.2f}] {' -> '.join(x['history']) or 'input'}\n{x['text']}\n")
  return 0
 except (OSError,ValueError) as exc: print(f"error: {exc}",file=sys.stderr); return 2
if __name__ == "__main__": raise SystemExit(main())
