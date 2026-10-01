# Roadmap / backlog

Working through this list top-down: pick the first unchecked item, implement it
with tests (and docs where relevant), and check it off in the same commit. Keep
each item small enough to finish in one sitting. Only real, tested work lands,
never an empty commit.

## Tests & coverage
- [x] Add edge-case tests for `PIIValidator` phone formats (intl, extensions, false positives like ISBNs).
- [x] Add tests for `_apply_redactions` with adjacent and nested spans.
- [x] Add tests for `SecretsValidator` Slack + Google + private-key (PEM) patterns.
- [x] Add a test that `GuardResult.by_validator` filters correctly across a 3-validator pipeline, and returns `[]` for an unknown validator name.
- [x] Add direct unit tests for the `_luhn_ok` helper (known valid + invalid card numbers).
- [x] Add tests asserting clean text is returned unchanged and `passed` is True for every validator (empty string, whitespace, plain prose).
- [x] Add tests for `GuardResult` properties (`passed`, `blocked`, `redacted`, `__bool__`) across allow/redact/block combinations.
- [x] Add tests for `Finding` dataclass defaults (severity MEDIUM, empty meta) and `Action`/`Severity` string-enum equality.
- [x] Add a parametrized test that every `InjectionValidator` pattern label fires on a representative example.
- [x] Add tests that `InjectionValidator` matching is case-insensitive.
- [x] Add tests for `SecretsValidator` with multiple secrets in one string (all reported).
- [x] Add tests for `JSONSchemaValidator` with nested schemas (arrays + nested required fields).
- [x] Add a test for `JSONSchemaValidator` where valid JSON has the wrong top-level type (array vs object).
- [x] Add tests for `PIIValidator` with two adjacent PII items, asserting both redacted and surrounding text preserved.
- [x] Add tests distinguishing space- vs hyphen-separated credit cards (both redacted).
- [x] Add tests that an SSN embedded in a longer digit run is NOT matched.
- [x] Add tests that IPv4 findings carry LOW severity and `kind == "ip_address"`.
- [x] Add tests for `Guard()` with no validators (passes, text unchanged) and `Guard.add` returning self for chaining.
- [x] Add a `tests/conftest.py` with shared fixtures (sample guards) and refactor a couple of tests to use them.

## New validators
- [x] `ToxicityValidator` — keyword/lexicon baseline with a labeled dataset + eval.
- [x] `TopicValidator` — allow/deny topic lists (e.g. block medical/legal advice).
- [x] `LengthValidator` — min/max word or char bounds on output.
- [x] `PIIValidator`: add IBAN (real mod-97 checksum) and passport-number patterns.
- [ ] `LanguageValidator` — deferred on purpose. Real language ID without a dependency means either a weak heuristic (stopword ratio, easy to game, wrong on short text) or pulling in a model/dictionary, which breaks the zero-dependency core. Worth doing properly as an optional extra later, not worth shipping a weak baseline just to check the box.

## Evals & datasets
- [x] Add `datasets/pii_labeled.jsonl` and `evals/eval_pii.py`. 28 rows, each verified against the real validator before being added, including real limitations (North-American-only phone format misses intl numbers; the passport `\d{9}` pattern can't distinguish a passport from any other 9-digit ID by shape alone). precision=0.938 recall=0.882 f1=0.909, honest numbers from real gaps, not a hand-picked 1.000.
- [x] Add a combined-pipeline eval (`datasets/combined_labeled.jsonl`, `evals/eval_combined.py`) reporting both end-to-end and per-validator catch-rate metrics. Scope is composition correctness (do the validators work together, is routing right), not re-measuring each validator's own precision/recall, that's what the per-validator evals are for.
- [ ] Grow `injection_labeled.jsonl` toward 100 rows (harder negatives, obfuscated positives). Deferred: real work (sourcing genuinely hard adversarial cases), not something to pad out with filler rows just to hit a number.
- [ ] Reduce injection false-positive rate below 0.05 without dropping recall. Deferred, needs the larger dataset above first to know what's actually failing.

## Docs & examples
- [x] `examples/fastapi_middleware.py`: guard requests/responses in a web app.
- [x] `examples/streaming.py`: apply output guards to streamed tokens.
- [x] `examples/custom_validator.py`: subclass `Validator` to add a project-specific rule.
- [x] `examples/batch_scan.py`: scan a list of texts and print a per-validator summary.
- [x] `examples/cli_scan.py`: read text from stdin, print findings as JSON.
- [x] Add status badges (Python version, license, tests) to the top of the README. Already present.
- [x] Docstring pass: `InjectionValidator`, `PIIValidator`, `JSONSchemaValidator`, `SecretsValidator`, and `ToxicityValidator` now each carry a doctest-style usage example, verified with `python -m doctest` (0 failures across 9 doctests, `Guard`'s existing one plus these 5 new ones). `LengthValidator` and `TopicValidator` already had full examples from when they were added.
- [x] `CONTRIBUTING.md` and a short ASCII architecture diagram in the README.
- [x] `CHANGELOG.md` starting at v0.1.0 (Keep a Changelog format), built from the real commit history, not invented.
- [x] Add a "Writing a custom validator" section to the README.
- [x] Add a "Threat model & scope" section to the README (what bulwark does and does not catch, including the passport-pattern ambiguity documented honestly rather than hidden).
- [x] Add a `docs/validators.md` API reference, one runnable snippet per validator, every snippet verified to produce the exact output shown before being committed.
- [x] Add `docs/evaluation.md` explaining precision / recall / F1 / false-positive-rate, and why `eval_combined.py`'s near-perfect numbers measure something different from the per-validator evals.
- [x] Expand the README quickstart with a `JSONSchemaValidator` example using a real schema.
- [x] Module-level docstrings: already present on every file (checked), module docstrings didn't need the gap this item assumed.

## Optional / stretch
- [ ] `LLMJudgeValidator`: pluggable judge interface (offline stub + real backend). Deliberately left for a true v2: this needs a real design decision about the judge interface (sync vs async, how a judge reports confidence) that shouldn't be rushed just to close out a roadmap.
- [ ] Config loading from YAML so a Guard can be declared without code. Deliberately left: needs a real schema design for the YAML shape, not just a quick `yaml.safe_load` wrapper.
