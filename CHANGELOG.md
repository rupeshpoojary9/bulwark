# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- `LengthValidator`: min/max character or word bounds on output, independent of each other.
- `TopicValidator`: deny-mode blocks on a matched topic; allow-mode blocks unless at least one allowed topic matched.
- `PIIValidator`: IBAN detection with a real ISO 7064 mod-97-10 checksum, and a deliberately conservative passport-number pattern.
- `ToxicityValidator`: keyword/lexicon baseline for abusive language (threats, insults, profanity), with a labeled dataset and eval.
- `evals/eval_pii.py` and `datasets/pii_labeled.jsonl`: 28 rows, every one verified against the real validator before being added. Includes honest known limitations (the phone pattern is North-American only; the passport pattern can't distinguish a real passport from any other 9-digit ID by shape alone).
- `evals/eval_combined.py` and `datasets/combined_labeled.jsonl`: runs the full validator stack together, reporting end-to-end and per-validator catch-rate metrics.
- `examples/fastapi_middleware.py`, `examples/streaming.py`, `examples/custom_validator.py`, `examples/batch_scan.py`, `examples/cli_scan.py`.
- `CONTRIBUTING.md`, this changelog, and a validator API reference in `docs/validators.md`.
- `tests/conftest.py` with shared `Guard` fixtures.
- CI: pytest across Python 3.10 to 3.12 on every push and pull request.

### Changed
- README: added a "Writing a custom validator" section, a "Threat model & scope" section, an ASCII architecture diagram, and an expanded quickstart covering `JSONSchemaValidator`.

## [0.1.0] - 2026-09-21

### Added
- `Guard`: composes validators into a pipeline, applies `REDACT` transforms in one place so overlapping spans and ordering are handled correctly once.
- `PIIValidator`: emails, phone numbers (North-American format), SSNs, credit cards (Luhn-checked), IPv4 addresses.
- `InjectionValidator`: prompt-injection and jailbreak pattern detection.
- `SecretsValidator`: leaked API keys and tokens (AWS, OpenAI, GitHub, Slack, Google, PEM private keys).
- `JSONSchemaValidator`: structured-output validation against a JSON Schema.
- `evals/eval_injection.py` and `datasets/injection_labeled.jsonl`: precision/recall/F1/false-positive-rate scoring against a labeled dataset, the pattern every later eval follows.
- Initial test suite, README, MIT license.
- CI: pytest on push, plus tests/license/Python-version badges.
