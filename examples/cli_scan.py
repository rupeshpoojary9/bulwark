"""Read text from stdin, run it through a Guard, and print findings as JSON.

A tiny command-line front end for bulwark, handy for shell pipelines, git
hooks, or CI jobs that need to check a file or a model response:

    echo "mail me at jane@example.com" | python examples/cli_scan.py
    python examples/cli_scan.py --only pii,secrets < response.txt
    cat prompt.txt | python examples/cli_scan.py --compact | jq .blocked

For the first command the JSON report is (spans index into the original
input; `echo` appends the trailing newline):

    {
      "passed": true,
      "blocked": false,
      "redacted": true,
      "text": "mail me at [REDACTED_EMAIL]\\n",
      "findings": [
        {"validator": "pii", "action": "redact", "severity": "medium",
         "message": "email detected", "span": [11, 27],
         "replacement": "[REDACTED_EMAIL]", "meta": {"kind": "email"}}
      ]
    }

Exit status is 0 when the text passed, 1 when any validator blocked it, and 2
on a usage error — so the script can gate a pipeline directly.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from bulwark import (
    Finding,
    Guard,
    GuardResult,
    InjectionValidator,
    PIIValidator,
    SecretsValidator,
    ToxicityValidator,
    Validator,
)

# Every validator that makes sense on free text, keyed by its `name`.
# JSONSchemaValidator is left out: it needs a schema to be useful.
AVAILABLE: dict[str, type[Validator]] = {
    cls.name: cls
    for cls in (InjectionValidator, PIIValidator, SecretsValidator, ToxicityValidator)
}


def build_guard(only: list[str] | None) -> Guard:
    names = only or list(AVAILABLE)
    unknown = [n for n in names if n not in AVAILABLE]
    if unknown:
        raise ValueError(
            f"unknown validator(s): {', '.join(unknown)} "
            f"(choose from: {', '.join(AVAILABLE)})"
        )
    return Guard([AVAILABLE[n]() for n in names])


def finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "validator": f.validator,
        "action": f.action.value,
        "severity": f.severity.value,
        "message": f.message,
        "span": list(f.span) if f.span is not None else None,
        "replacement": f.replacement,
        "meta": f.meta,
    }


def result_to_dict(result: GuardResult) -> dict[str, Any]:
    return {
        "passed": result.passed,
        "blocked": result.blocked,
        "redacted": result.redacted,
        "text": result.text,
        "findings": [finding_to_dict(f) for f in result.findings],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Scan text from stdin with bulwark and print findings as JSON.",
    )
    parser.add_argument(
        "--only",
        help="comma-separated validator names to run "
             f"(default: all of {', '.join(AVAILABLE)})",
    )
    parser.add_argument(
        "--compact", action="store_true",
        help="print single-line JSON instead of pretty-printed output",
    )
    args = parser.parse_args(argv)

    only = [n.strip() for n in args.only.split(",") if n.strip()] if args.only else None
    try:
        guard = build_guard(only)
    except ValueError as exc:
        parser.error(str(exc))  # exits with status 2

    result = guard.check(sys.stdin.read())
    json.dump(
        result_to_dict(result), sys.stdout,
        indent=None if args.compact else 2,
        ensure_ascii=False,
        default=str,  # keep output valid even if a custom validator puts odd types in meta
    )
    sys.stdout.write("\n")
    return 0 if result.passed else 1


if __name__ == "__main__":
    sys.exit(main())
