from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .search import DEFAULT_OPERATIONS, SearchConfig, run_search


def _read_input(args: argparse.Namespace) -> str:
    choices = [args.ciphertext is not None, args.input is not None, args.file is not None]
    if sum(1 for c in choices if c) > 1:
        raise ValueError("Specify only one of positional ciphertext, --input, or --file.")

    if args.ciphertext is not None:
        return args.ciphertext
    if args.input is not None:
        return args.input
    if args.file is not None:
        return Path(args.file).read_text(encoding="utf-8")

    data = sys.stdin.read()
    if not data:
        raise ValueError("No input provided. Pass ciphertext, --input, --file, or stdin.")
    return data.rstrip("\n")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cipher-bruteforce",
        description="Heuristic brute-force cryptanalysis for classic ciphers/encodings.",
    )
    parser.add_argument("ciphertext", nargs="?", help="Ciphertext input")
    parser.add_argument("--input", help="Ciphertext input string")
    parser.add_argument("--file", help="Path to file containing ciphertext")
    parser.add_argument("--format", choices=("human", "json"), default="human")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--beam-width", type=int, default=80)
    parser.add_argument("--top", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument(
        "--operations",
        default=",".join(sorted(DEFAULT_OPERATIONS - {"identity"})),
        help="Comma-separated operations: base64,hex,rot13,caesar,atbash,substitution,vigenere,railfence,xor",
    )
    parser.add_argument("--max-rails", type=int, default=12)
    parser.add_argument("--xor-key-limit", type=int, default=256)
    parser.add_argument("--xor-printable-threshold", type=float, default=0.70)

    parser.add_argument("--vigenere-key", action="append", default=[])
    parser.add_argument("--vigenere-key-file", help="One Vigenere key per line")
    parser.add_argument("--vigenere-auto-max-key-length", type=int, default=0)
    parser.add_argument("--vigenere-auto-top-shifts", type=int, default=2)
    parser.add_argument("--vigenere-auto-max-keys", type=int, default=200)

    parser.add_argument("--substitution-key", action="append", default=[])
    parser.add_argument("--substitution-restarts", type=int, default=8)
    parser.add_argument("--substitution-iterations", type=int, default=2000)
    parser.add_argument("--substitution-top-k", type=int, default=4)
    parser.add_argument("--seed", type=int, default=1337)
    return parser


def _normalize_operations(raw: str) -> set[str]:
    if not raw.strip():
        return set(DEFAULT_OPERATIONS)
    allowed = DEFAULT_OPERATIONS - {"identity"}
    selected = {part.strip().lower() for part in raw.split(",") if part.strip()}
    unknown = sorted(selected - allowed)
    if unknown:
        raise ValueError(f"Unknown operations: {', '.join(unknown)}")
    return selected | {"identity"}


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        text = _read_input(args)
        operations = _normalize_operations(args.operations)
    except (ValueError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    vigenere_keys = list(args.vigenere_key)
    if args.vigenere_key_file:
        try:
            for line in Path(args.vigenere_key_file).read_text(encoding="utf-8").splitlines():
                key = line.strip()
                if key:
                    vigenere_keys.append(key)
        except OSError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2

    config = SearchConfig(
        depth=max(1, args.depth),
        beam_width=max(1, args.beam_width),
        top_n=max(1, args.top),
        timeout_seconds=max(0.05, args.timeout),
        operations=operations,
        max_rails=max(2, args.max_rails),
        xor_key_limit=max(0, min(256, args.xor_key_limit)),
        xor_printable_threshold=max(0.0, min(1.0, args.xor_printable_threshold)),
        vigenere_keys=vigenere_keys,
        vigenere_auto_max_key_length=max(0, args.vigenere_auto_max_key_length),
        vigenere_auto_top_shifts=max(1, args.vigenere_auto_top_shifts),
        vigenere_auto_max_keys=max(1, args.vigenere_auto_max_keys),
        substitution_keys=list(args.substitution_key),
        substitution_restarts=max(1, args.substitution_restarts),
        substitution_iterations=max(10, args.substitution_iterations),
        substitution_top_k=max(1, args.substitution_top_k),
        random_seed=args.seed,
    )

    results = run_search(text, config)

    if args.format == "json":
        payload = {
            "input": text,
            "heuristic_notice": "Ranked candidates are heuristic and not guaranteed decryptions.",
            "config": {
                "depth": config.depth,
                "beam_width": config.beam_width,
                "top_n": config.top_n,
                "timeout_seconds": config.timeout_seconds,
                "operations": sorted(config.operations),
            },
            "results": [item.as_json() for item in results],
        }
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0

    print("[notice] Ranked candidates are heuristic and not guaranteed decryptions.")
    print(f"Input: {text!r}")
    print(f"Operations: {', '.join(sorted(config.operations - {'identity'}))}")
    print()
    for idx, item in enumerate(results, start=1):
        chain = " -> ".join(item.chain)
        print(f"[{idx}] score={item.score:.3f} chain={chain}")
        print(f"    printable={item.score_breakdown.printable:.2f} english={item.score_breakdown.english:.2f} japanese={item.score_breakdown.japanese:.2f} penalty={item.score_breakdown.penalty:.2f}")
        print(f"    text={item.text!r}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
