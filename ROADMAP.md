# Roadmap / backlog

The daily contributor works through this list top-down: pick the first unchecked
item, implement it with tests (and docs where relevant), and check it off in the
same commit. Keep each item small enough to finish in one sitting. Only real,
tested work lands — never an empty commit.

## Tests & coverage
- [ ] Add edge-case tests for `PIIValidator` phone formats (intl, extensions, false positives like ISBNs).
- [ ] Add tests for `_apply_redactions` with adjacent and nested spans.
- [ ] Add tests for `SecretsValidator` Slack + Google + private-key patterns.
- [ ] Add a test that `GuardResult.by_validator` filters correctly across a 3-validator pipeline.
- [ ] Add property-based tests (hypothesis) that clean text is never modified.
- [ ] Measure and record coverage; add a coverage badge target of 90%+.

## New validators
- [ ] `ToxicityValidator` — keyword/lexicon baseline with a labeled dataset + eval.
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
- [ ] Docstring pass: ensure every public class/method has a usage example.
- [ ] `CONTRIBUTING.md` and a short architecture diagram in the README.

## Optional / stretch
- [ ] `LLMJudgeValidator` — pluggable judge interface (offline stub + real backend).
- [ ] Config loading from YAML so a Guard can be declared without code.
