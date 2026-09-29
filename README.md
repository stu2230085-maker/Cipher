# Cipher

Production-quality heuristic brute-force cryptanalysis CLI for learning and experimentation.

> ⚠️ **Important:** Output is heuristic ranking, not guaranteed decryption certainty.

## Features

- Candidate generation/decoding:
  - Base64
  - Hexadecimal
  - ROT13
  - Caesar (all shifts)
  - Atbash
  - Monoalphabetic substitution
  - Vigenère
  - Rail Fence
  - XOR (single-byte brute force)
- Multi-layer/chained transform search (beam search)
- Transparent scoring breakdown (printable, English, Japanese hint, penalties)
- Configurable depth, beam width, top-N, timeout/work limits, and operation filters
- Human-readable and JSON output
- CLI input from positional argument, `--input`, file, or stdin

## Installation

```bash
python -m pip install -e .
```

## CLI usage

```bash
cipher-bruteforce "uryyb"
```

### Input modes

```bash
cipher-bruteforce "aGVsbG8="
cipher-bruteforce --input "68656c6c6f" --operations hex
cipher-bruteforce --file ./cipher.txt
cat cipher.txt | cipher-bruteforce
```

### JSON output

```bash
cipher-bruteforce "uryyb" --operations rot13 --format json
```

### Chained decode example

```bash
# "uryyb" encoded as hex => 7572797962
cipher-bruteforce "7572797962" --operations hex,rot13 --depth 2 --top 5
```

### Vigenère options

```bash
cipher-bruteforce "LXFOPVEFRNHR" --operations vigenere --vigenere-key LEMON
cipher-bruteforce "..." --operations vigenere --vigenere-key-file ./keys.txt
cipher-bruteforce "..." --operations vigenere --vigenere-auto-max-key-length 4 --vigenere-auto-max-keys 200
```

### Monoalphabetic substitution options

```bash
cipher-bruteforce "..." --operations substitution --substitution-restarts 12 --substitution-iterations 3000 --seed 1337
cipher-bruteforce "..." --operations substitution --substitution-key QWERTYUIOPASDFGHJKLZXCVBNM
```

### XOR options

```bash
cipher-bruteforce "..." --operations xor --xor-key-limit 64 --xor-printable-threshold 0.75
```

## Architecture

- `src/cipher_bruteforce/transforms.py`: deterministic transform/decoder primitives
- `src/cipher_bruteforce/scoring.py`: pluggable, transparent scoring model
- `src/cipher_bruteforce/attacks.py`: practical heuristic attacks (substitution hill climbing, Vigenère bounded key generation)
- `src/cipher_bruteforce/search.py`: bounded beam search over chained transforms
- `src/cipher_bruteforce/cli.py`: CLI and output formatting

## Algorithm notes and limitations

- Monoalphabetic substitution is solved with reproducible heuristic hill climbing (seeded random restarts), not exhaustive `26!` search.
- Vigenère support uses user-supplied keys and optional bounded frequency-analysis key generation (`--vigenere-auto-*`) with explicit limits.
- XOR currently supports single-byte brute force only.
- Scoring is optimized for English plaintext and includes lightweight Unicode/Japanese hints. It is not a full multilingual language model.
- Heuristic ranking can produce false positives and should be interpreted cautiously.

## Reproducibility and safety

- Deterministic behavior can be improved by fixing `--seed`.
- Runtime is bounded by depth/beam/timeout and operation-specific limits.
- No runtime network access is required.
- This tool is intended for legal/authorized cryptanalysis and education.

## Testing

```bash
python -m compileall -q src tests
PYTHONPATH=src python -m unittest discover -s tests -v
```

## CI

GitHub Actions workflow (`.github/workflows/ci.yml`) runs syntax checks and unit tests on pushes/PRs.

## License and third-party dependencies

- Current repository had no license file at implementation time.
- To avoid making an unapproved legal choice on behalf of the repository owner, this change does **not** add a new license.
- Implementation uses Python standard library only; no third-party runtime dependencies were added, so no NOTICE attribution file is required.
