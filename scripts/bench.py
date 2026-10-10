"""Scan+redact latency against the product targets (CLAUDE.md, principle 1).

    python scripts/bench.py [runs]

Targets: p99 <= 1 ms for payloads <= 4 KB, p99 < 10 ms for 128 KB. Run before and
after any change to detectors or the scan path, and report both. Not run in CI:
shared runners are too noisy for millisecond budgets.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from scanner import redact, scan  # noqa: E402

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


def _p99(text: str, runs: int) -> tuple:
    for _ in range(min(20, runs)):
        redact(text)
    samples = []
    for _ in range(runs):
        t0 = time.perf_counter_ns()
        redact(text)
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
            p50, p99 = _p99(text, runs if size <= 4096 else max(30, runs // 10))
            ok = p99 <= target if size <= 4096 else p99 < target
            misses += not ok
            print(f"  {'ok  ' if ok else 'MISS'} {name:22} {len(scan(text)):5} findings   "
                  f"p50 {p50:7.3f} ms   p99 {p99:7.3f} ms")
    print(f"\n{misses} case(s) over target" if misses else "\nall cases within target")
    return 1 if misses else 0


if __name__ == "__main__":
    sys.exit(main())
