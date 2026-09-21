# Roadmap / backlog

The daily contributor works through this list top-down: pick the first unchecked
item, implement it with tests (and docs where relevant), and check it off in the
same commit. Keep each item small enough to finish in one sitting. Only real,
tested work lands — never an empty commit.

## Tests & coverage
- [x] Add edge-case tests for `PIIValidator` phone formats (intl, extensions, false positives like ISBNs).
- [x] Add tests for `_apply_redactions` with adjacent and nested spans.
- [x] Add tests for `SecretsValidator` Slack + Google + private-key (PEM) patterns.
- [x] Add a test that `GuardResult.by_validator` filters correctly across a 3-validator pipeline, and returns `[]` for an unknown validator name.
- [x] Add direct unit tests for the `_luhn_ok` helper (known valid + invalid card numbers).
- [x] Add tests asserting clean text is returned unchanged and `passed` is True for every validator (empty string, whitespace, plain prose).
- [ ] Add tests for `GuardResult` properties (`passed`, `blocked`, `redacted`, `__bool__`) across allow/redact/block combinations.
- [ ] Add tests for `Finding` dataclass defaults (severity MEDIUM, empty meta) and `Action`/`Severity` string-enum equality.
- [ ] Add a parametrized test that every `InjectionValidator` pattern label fires on a representative example.
- [ ] Add tests that `InjectionValidator` matching is case-insensitive.
- [ ] Add tests for `SecretsValidator` with multiple secrets in one string (all reported).
- [ ] Add tests for `JSONSchemaValidator` with nested schemas (arrays + nested required fields).
- [ ] Add a test for `JSONSchemaValidator` where valid JSON has the wrong top-level type (array vs object).
- [ ] Add tests for `PIIValidator` with two adjacent PII items, asserting both redacted and surrounding text preserved.
- [ ] Add tests distinguishing space- vs hyphen-separated credit cards (both redacted).
- [ ] Add tests that an SSN embedded in a longer digit run is NOT matched.
- [ ] Add tests that IPv4 findings carry LOW severity and `kind == "ip_address"`.
- [ ] Add tests for `Guard()` with no validators (passes, text unchanged) and `Guard.add` returning self for chaining.
- [ ] Add a `tests/conftest.py` with shared fixtures (sample guards) and refactor a couple of tests to use them.

## New validators
- [x] `ToxicityValidator` — keyword/lexicon baseline with a labeled dataset + eval.
- [ ] `TopicValidator` — allow/deny topic lists (e.g. block medical/legal advice).
- [ ] `LengthValidator` — min/max token or char bounds on output.
- [ ] `LanguageValidator` — flag output not in an expected language.
- [ ] `PIIValidator`: add IBAN and passport-number patterns.

## Evals & datasets
- [ ] Grow `injection_labeled.jsonl` toward 100 rows (harder negatives, obfuscated positives).
- [ ] Add `datasets/pii_labeled.jsonl` and `evals/eval_pii.py`.
- [ ] Add a combined-pipeline eval reporting per-validator and end-to-end metrics.
- [ ] Reduce injection false-positive rate below 0.05 without dropping recall.

## Docs & examples
- [ ] `examples/fastapi_middleware.py` — guard requests/responses in a web app.
- [ ] `examples/streaming.py` — apply output guards to streamed tokens.
- [ ] `examples/custom_validator.py` — subclass `Validator` to add a project-specific rule.
- [ ] `examples/batch_scan.py` — scan a list of texts and print a per-validator summary.
- [ ] `examples/cli_scan.py` — read text from stdin, print findings as JSON.
- [ ] Docstring pass: ensure every public class/method has a usage example.
- [ ] `CONTRIBUTING.md` and a short architecture diagram (ASCII) in the README.
- [ ] `CHANGELOG.md` starting at v0.1.0 (Keep a Changelog format).
- [ ] Add a "Writing a custom validator" section to the README.
- [ ] Add a "Threat model & scope" section to the README (what bulwark does and does not catch).
- [ ] Add a `docs/validators.md` API reference with one runnable snippet per validator.
- [ ] Add a "How the eval works" doc explaining precision / recall / F1 / false-positive-rate.
- [ ] Add status badges (Python version, license, tests) to the top of the README.
- [ ] Expand the README quickstart with a `JSONSchemaValidator` example using a real schema.
- [ ] Add module-level docstrings with usage notes to any file missing one.

## Optional / stretch
- [ ] `LLMJudgeValidator` — pluggable judge interface (offline stub + real backend).
- [ ] Config loading from YAML so a Guard can be declared without code.
