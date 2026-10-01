# Contributing

bulwark is small on purpose. Contributions that keep it that way are the
easiest to merge.

## Setup

```bash
git clone https://github.com/rupeshpoojary9/bulwark.git
cd bulwark
pip install -e ".[dev]"
pytest -q
```

No network access or API key is needed for anything in this repo, including
the evals.

## Ground rules

- **Zero core dependencies.** The `bulwark` package itself has none. If an
  idea needs one, it goes behind an optional extra (see `schema` in
  `pyproject.toml` for the pattern), never into the required install.
- **Every validator follows the same contract.** A `name` and a
  `check(text) -> list[Finding]` method, as documented in `Validator`
  (`bulwark/validators/base.py`). Validators never mutate the input text; the
  `Guard` applies redactions in one place so overlapping spans are handled
  correctly once, not per-validator.
- **No empty or no-op commits.** If a change doesn't do anything real, it
  doesn't land, see `ROADMAP.md`'s own rule for the daily contribution
  process this repo is built with.
- **Real tests, not padding.** A test should fail without the change it's
  testing and pass with it. If you can delete the implementation and the test
  still passes, it isn't testing anything.

## Adding a validator

1. Create `bulwark/validators/your_thing.py`, subclassing `Validator`.
2. Export it from `bulwark/validators/__init__.py` and `bulwark/__init__.py`.
3. Add tests in `tests/test_your_thing.py` covering the real behavior: what
   it catches, what it correctly leaves alone, and the edge cases that would
   trip up a naive implementation (see `tests/test_pii.py` for the shape:
   false positives like ISBNs or invalid card numbers get their own tests,
   not just the happy path).
4. If the validator makes a quantifiable claim (an eval, a precision/recall
   number), back it with a labeled dataset in `datasets/` and a script in
   `evals/` following the pattern in `evals/eval_injection.py`. Verify every
   row of a new dataset against the real implementation before committing it,
   don't guess at what the regex will match.
5. Update the validator table in `README.md` and `ROADMAP.md`.

## Pull requests

- Keep each PR to one real, focused change.
- Run `pytest -q` and, if you touched a validator with an eval, the relevant
  `python -m evals.eval_*` before opening the PR, and mention the numbers in
  the description if they moved.
- Describe what changed and why in plain language, not just what files moved.
