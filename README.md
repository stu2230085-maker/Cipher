# Cipher

A standard-library-only, bounded cryptanalysis learning tool. It produces *plausible candidates*, not verified decryptions; independently verify every result.

## Setup and usage

Requires Python 3.10+. From a checkout run `python -m pip install -e .`, then:

```sh
cipher-tool 'Uryyb, jbeyq!' --operations rot13 --depth 1
cipher-tool 'U0dWc2JHOD0=' --operations base64,rot13 --depth 2 --json
cipher-tool --file cipher.txt --depth 3 --beam-width 20 --max-work 1000
cat cipher.txt | cipher-tool --stdin --operations xor --top 5
cipher-tool 'Lxfopv ef rnhr!' --operations vigenere --vigenere-key lemon
```

Operations include Base64, hex, ROT13, all Caesar shifts, Atbash, rail-fence decryption (rails 2–9), single-byte XOR, and supplied-key Vigenère. The reusable `substitution_decrypt` helper and deterministic frequency baseline support monoalphabetic experiments; it is deliberately a limited heuristic, not a `26!` search. Vigenère search only tries explicit `--vigenere-key` values or lines from `--key-file`; it has no unbounded statistical key search.

## Architecture

`operations.py` contains pure byte transforms, `scoring.py` provides independent English and UTF-8/Unicode baselines, and `search.py` performs duplicate-suppressed beam search. Histories show each transformation. English scores reward printable text, letters, and common words; the Unicode baseline rewards valid printable UTF-8, including Japanese but does **not** provide Japanese language identification.

## Safety and development

Default search limits are depth 2, beam width 20, 1,000 work units, and two seconds. Accepted caps are depth 5, beam 100, and 10,000 work units. Binary output is replacement-decoded for display; JSON contains the same human-readable text. Run `python -m unittest discover -s tests` and `python -m cipher_tool.cli --help`.

No runtime dependencies, external network requests, or third-party code/assets are used. This repository currently has no license; licensing requires owner review.
