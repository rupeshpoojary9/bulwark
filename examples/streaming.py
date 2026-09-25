"""Apply output guards to a streamed LLM response, token by token.

Guarding a stream is harder than guarding a finished string: a secret or an
email address can arrive split across several chunks, and once a chunk has
been shown to the user it cannot be taken back. This example handles that by:

  * re-checking the *whole* accumulated text every time a chunk arrives, so
    patterns that span chunk boundaries are still caught;
  * holding back the last ``holdback`` characters (a small lookahead window)
    so a half-streamed secret or email is never released before it becomes
    recognisable;
  * never releasing text that sits inside a pending redaction span; and
  * stopping the stream the moment any validator asks to BLOCK.

The trade-off is latency: the user sees text ``holdback`` characters behind
the model. Pick ``holdback`` a little larger than the longest thing you need
to recognise (API keys here are ~40-50 chars).

Run it with:

    python examples/streaming.py
"""
from __future__ import annotations

from typing import Iterable, Iterator

from bulwark import (
    Action,
    Finding,
    Guard,
    GuardResult,
    PIIValidator,
    SecretsValidator,
)


class StreamBlocked(Exception):
    """Raised when the accumulated stream trips a BLOCK finding."""

    def __init__(self, result: GuardResult) -> None:
        self.result = result
        reasons = [f.message for f in result.findings if f.action is Action.BLOCK]
        super().__init__(f"stream blocked: {reasons}")


def _redact_window(text: str, findings: list[Finding], lo: int, hi: int) -> str:
    """Return ``text[lo:hi]`` with every REDACT span that lies inside it masked.

    Overlapping spans are collapsed the same way ``Guard`` does it: sorted by
    start, widest first, and any span starting inside a kept one is dropped.
    """
    spans = sorted(
        (f.span for f in findings
         if f.action is Action.REDACT and f.span is not None
         and lo <= f.span[0] and f.span[1] <= hi),
        key=lambda s: (s[0], -s[1]),
    )
    repl = {f.span: f.replacement or "[REDACTED]" for f in findings
            if f.action is Action.REDACT and f.span is not None}
    out, pos = [], lo
    for start, end in spans:
        if start < pos:
            continue
        out.append(text[pos:start])
        out.append(repl[(start, end)])
        pos = end
    out.append(text[pos:hi])
    return "".join(out)


def _safe_end(findings: list[Finding], emitted: int, candidate: int) -> int:
    """Pull ``candidate`` back so it never cuts through a REDACT span."""
    end = candidate
    for f in findings:
        if f.action is Action.REDACT and f.span is not None:
            start, stop = f.span
            if start < end < stop:
                end = start
    return max(end, emitted)


def guard_stream(
    chunks: Iterable[str], guard: Guard, holdback: int = 64
) -> Iterator[str]:
    """Yield guarded pieces of a streamed response.

    Raises :class:`StreamBlocked` as soon as the text seen so far is blocked;
    anything already yielded was clean at the time it was released.
    """
    buf = ""
    emitted = 0  # how many chars of `buf` have been released to the caller
    for chunk in chunks:
        buf += chunk
        result = guard.check(buf)
        if result.blocked:
            raise StreamBlocked(result)
        end = _safe_end(result.findings, emitted, len(buf) - holdback)
        if end > emitted:
            yield _redact_window(buf, result.findings, emitted, end)
            emitted = end

    # Stream finished: nothing more can arrive, so flush the held-back tail.
    result = guard.check(buf)
    if result.blocked:
        raise StreamBlocked(result)
    if emitted < len(buf):
        yield _redact_window(buf, result.findings, emitted, len(buf))


def fake_llm_stream(text: str, size: int = 5) -> Iterator[str]:
    """Stand-in for a real streaming LLM: yields ``text`` in small chunks."""
    for i in range(0, len(text), size):
        yield text[i:i + size]


def main() -> None:
    output_guard = Guard([SecretsValidator(), PIIValidator()])

    # 1) PII split across chunks is still redacted before it is shown.
    reply = ("Sure! You can reach our support lead at jane.doe@example.com "
             "or call 415-555-0132 during business hours.")
    print("--- redacting stream ---")
    shown = "".join(guard_stream(fake_llm_stream(reply), output_guard))
    print(shown)
    assert "jane.doe@example.com" not in shown
    assert "[REDACTED_EMAIL]" in shown and "[REDACTED_PHONE]" in shown

    # 2) A leaked credential stops the stream; the key itself never escapes.
    leaky = ("Here is the config you asked for. Set OPENAI_API_KEY to "
             "sk-abcdefghijklmnopqrstuvwx1234 and restart the service.")
    print("\n--- blocking stream ---")
    shown = ""
    try:
        for piece in guard_stream(fake_llm_stream(leaky), output_guard):
            shown += piece
    except StreamBlocked as exc:
        print(f"released before block: {shown!r}")
        print(exc)
    assert "sk-" not in shown


if __name__ == "__main__":
    main()
