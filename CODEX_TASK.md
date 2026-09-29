# Codex Cloud Task: Build a Cipher Brute-Force and Cryptanalysis Tool

## Objective

Implement a production-quality, extensible cryptanalysis tool in this repository. The tool should generate, rank, and display plausible plaintext candidates for ciphertexts that may use one or more of the following transformations:

- Base64
- Hexadecimal
- ROT13
- Caesar cipher
- Atbash
- Monoalphabetic substitution
- Vigenère cipher
- Rail Fence cipher
- XOR

The implementation must support chained transformations because challenge ciphertexts are often encoded or encrypted in multiple layers.

## Repository and branch

- Repository: `stu2230085-maker/Cipher`
- Target branch: `implement-cipher-tool`
- Base branch for the eventual PR: `main`

## Important constraints

1. Inspect the repository before changing it and preserve useful existing conventions.
2. Do not copy CyberChef source code or other copyrighted implementation wholesale. Use public projects only as conceptual references.
3. Prefer a standard-library-only implementation unless a dependency provides clear value.
4. Do not make network requests at runtime.
5. Add resource limits so arbitrary input cannot cause unbounded CPU or memory use.
6. Make heuristic results explicit: the tool must not claim that the highest-scoring candidate is certainly correct.
7. Use deterministic behavior by default. If randomized search is used, expose a seed and test it with a fixed seed.

## Recommended project structure

Choose a structure appropriate for the existing repository. A Python implementation is acceptable and preferred if no language has already been established. A possible layout is:

```text
src/
  cipher_tool/
    __init__.py
    cli.py
    models.py
    operations/
      __init__.py
      encodings.py
      classical.py
      substitution.py
      xor.py
    scoring/
      __init__.py
      base.py
      english.py
      unicode.py
    search.py
tests/
README.md
LICENSE
NOTICE
pyproject.toml
.github/workflows/ci.yml
```

Do not force this exact layout if the repository already has an established structure.

## Functional requirements

### Cipher and encoding operations

Implement tested functions for:

- Base64 decoding with malformed-input handling.
- Hexadecimal decoding with whitespace support where reasonable and clear errors for invalid input.
- ROT13.
- Caesar shifts, including all 26 shifts.
- Atbash.
- Rail Fence decryption for a bounded rail range.
- Single-byte XOR brute force for keys `0..255`.
- Optional repeating-key XOR only if it can be implemented cleanly with safe bounds.
- Vigenère decryption with supplied keys.
- Practical Vigenère key-search support using a supplied key list and/or bounded frequency-analysis mode.
- Monoalphabetic substitution solving through a practical heuristic, such as n-gram scoring plus hill climbing or simulated annealing. Never enumerate all `26!` substitutions.

### Chained search

Build an extensible search engine that can apply operations in sequence. It should provide:

- Maximum search depth.
- Beam width or another explicit candidate-pruning mechanism.
- Operation allow-list/filtering.
- Maximum candidates/work units.
- Optional timeout.
- Duplicate-state suppression.
- Transformation history for every result.
- Clear handling of binary output and undecodable bytes.

### Scoring

Create a pluggable scoring interface. Include at least:

- A transparent English-oriented score based on printable characters, word frequencies, and/or n-grams.
- A Unicode/Japanese-friendly baseline that does not incorrectly reject valid non-ASCII text. If Japanese language scoring is limited, document that limitation precisely.
- Tests showing that known plaintext ranks above obviously random/control-character output.

Scores are ranking signals, not proof of decryption.

### CLI

Provide a documented command-line interface supporting:

- Direct input argument.
- File input.
- Standard input.
- Human-readable output.
- JSON output.
- `--depth`.
- `--beam-width`.
- `--top`.
- `--max-work` or equivalent.
- `--timeout` or equivalent.
- Operation filtering.
- Vigenère key arguments and/or key-file input.
- Reproducible random seed where relevant.
- Useful exit codes and actionable error messages.

Avoid exposing dangerous defaults that allow excessive resource consumption.

## Testing requirements

Add unit and integration tests covering:

- Every required cipher operation.
- Known encryption/decryption pairs.
- Base64 and hex malformed inputs.
- Single-byte XOR known key recovery or ranking.
- Rail Fence edge cases such as one rail and too many rails.
- Vigenère supplied-key decryption and bounded search.
- Monoalphabetic solver smoke test with a short known fixture and deterministic seed.
- Chained transformation, for example plaintext -> ROT13 -> Base64 and recovery of the plaintext.
- Candidate scoring and ranking.
- Duplicate suppression and search limits.
- CLI direct input, stdin/file input, JSON output, invalid arguments, and resource-limit behavior.

Tests must be deterministic and runnable from a fresh checkout.

## Documentation requirements

Update or create `README.md` with:

1. Project purpose.
2. Installation/setup instructions.
3. CLI usage and examples for every required operation.
4. A chained-decode example.
5. Architecture overview.
6. Explanation of scoring and beam search.
7. Monoalphabetic substitution limitations and heuristic approach.
8. Vigenère key-search limitations.
9. Resource limits and safe-use guidance.
10. A clear statement that output is heuristic and must be independently verified.
11. Development and test commands.
12. License and dependency-attribution decisions.

Add an `examples/` directory or equivalent fixtures if it improves usability.

## License and dependencies

Inspect the repository's current license state before adding files.

- If the repository has no license, add an appropriate permissive license only if that is consistent with the repository owner/project intent. Otherwise document the decision and ask for review in the PR.
- Prefer no third-party runtime dependencies.
- If dependencies are added, verify their licenses and record attribution in `NOTICE` or an equivalent file when required.
- Do not claim that CyberChef code or assets are included.

## CI and quality

If CI is absent, add a GitHub Actions workflow that runs:

- Formatting or lint checks appropriate to the selected language.
- The complete test suite.
- Any type checking that is practical.

Keep the code typed, modular, readable, and documented. Avoid needless complexity, but do not reduce the implementation to a toy script.

## Completion checklist

Before opening the PR:

- [ ] All required operations are implemented.
- [ ] Chained search works and preserves operation history.
- [ ] Scoring is pluggable and documented.
- [ ] Monoalphabetic solving is heuristic rather than factorial brute force.
- [ ] Vigenère search has explicit bounded behavior.
- [ ] CLI supports argument, file, stdin, JSON, limits, and filters.
- [ ] Tests cover operations, chaining, malformed input, scoring, and CLI.
- [ ] README contains setup, examples, limitations, safety notes, and license information.
- [ ] Dependency licenses are accounted for.
- [ ] CI passes.
- [ ] The PR summary includes files changed, tests run, known limitations, and license decisions.
