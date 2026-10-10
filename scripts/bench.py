"""Scan+redact latency against the product targets (CLAUDE.md, principle 1).

    python scripts/bench.py [runs]

Targets: p99 <= 1 ms for payloads <= 4 KB, p99 < 10 ms for 128 KB. Each payload is also
timed through the gateway's request sanitizer (as an OpenAI chat body: JSON parse, scan,
re-serialize), which must meet the same targets. Run before and
after any change to detectors or the scan path, and report both. Not run in CI:
shared runners are too noisy for millisecond budgets.
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from gateway import sanitize_body  # noqa: E402  (stdlib-only; no [gateway] extra needed)
from scanner import DETECTORS, redact, scan  # noqa: E402

PROSE = ("Please summarise the attached quarterly roadmap and draft three follow-up questions for the "
         "platform team about latency budgets, staffing and the migration timeline. ")
CHAT = '{"role":"user","content":"' + PROSE * 3 + ' order #48213 on 2026-10-08, ticket 123-456-7890"},\n'
URLS = ("See https://docs.example.com/v2/guide?ref=abc and https://github.com/org/repo/pull/4821#issuecomment-99 "
        "for context; the dashboard is at https://grafana.internal:3000/d/x7Q. ")
LOG = ("2026-10-08T09:00:01Z,api-gateway,INFO,svc-chat,10.4.2.11,POST /v1/chat/completions model=gpt-4o "
       "tokens_in=812 status=200 latency_ms=341 trace=7f3a9c21e4b0\n")
DENSE = (ROOT / "tests" / "fixtures" / "sample_logs.csv").read_text()
CODE = (ROOT / "scanner.py").read_text()  # regex-heavy source full of secret-shaped strings
KINDS = [("prose prompt", PROSE), ("chat JSON", CHAT), ("prose with URLs", URLS), ("app log, clean", LOG),
         ("source code", CODE), ("log, ~1 secret/100 B", DENSE)]
TARGETS_MS = {4096: 1.0, 131072: 10.0}


def _sized(s: str, n: int) -> str:
    return (s * (n // len(s) + 1))[:n]


def _chat_body(text: str) -> bytes:
    """An OpenAI chat request carrying `text` split into ~2 KB messages."""
    msgs = [{"role": "user", "content": text[i:i + 2048]} for i in range(0, len(text), 2048)]
    return json.dumps({"model": "gpt-4o", "stream": True, "messages": msgs}).encode()


def _p99(fn, runs: int) -> tuple:
    for _ in range(min(20, runs)):
        fn()
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        fn()
        samples.append(time.perf_counter_ns() - t0)
    samples.sort()
    return samples[len(samples) // 2] / 1e6, samples[min(len(samples) - 1, int(len(samples) * 0.99))] / 1e6


def main() -> int:
    runs = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    misses = 0
    for size, target in TARGETS_MS.items():
        print(f"\n{size // 1024} KB payloads, target p99 {'<=' if size <= 4096 else '<'} {target:g} ms")
        for name, base in KINDS:
            text = _sized(base, size)
            n = runs if size <= 4096 else max(30, runs // 10)
            body = _chat_body(text)
            for label, fn in ((name, lambda: redact(text)),
                              ("  via gateway (JSON)", lambda: sanitize_body(body, "application/json", DETECTORS))):
                p50, p99 = _p99(fn, n)
                ok = p99 <= target if size <= 4096 else p99 < target
                misses += not ok
                count = f"{len(scan(text)):5} findings" if label == name else " " * 14
                print(f"  {'ok  ' if ok else 'MISS'} {label:22} {count}   p50 {p50:7.3f} ms   p99 {p99:7.3f} ms")
    print(f"\n{misses} case(s) over target" if misses else "\nall cases within target")
    return 1 if misses else 0


if __name__ == "__main__":
    sys.exit(main())
