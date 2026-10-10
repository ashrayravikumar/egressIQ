"""Fake LLM provider for demos and smoke tests: shows exactly what the gateway forwarded.

    python scripts/echo_upstream.py [--port 9000]
    egressiq gateway --upstream http://127.0.0.1:9000

Every request is printed here (method, path, body) and answered with an OpenAI-style
chat completion whose message content is the request body it received. Headers are not
echoed or printed (they carry the caller's API key).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class EchoHandler(BaseHTTPRequestHandler):
    def _reply(self) -> None:
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0)).decode("utf-8", "replace")
        print(f"--- upstream received {self.command} {self.path}\n{body}\n", flush=True)
        payload = json.dumps({
            "id": "chatcmpl-echo", "object": "chat.completion", "created": int(time.time()), "model": "echo",
            "choices": [{"index": 0, "finish_reason": "stop", "message": {"role": "assistant", "content": body}}],
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _reply

    def log_message(self, *args) -> None:
        pass


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--port", type=int, default=9000)
    args = p.parse_args()
    server = ThreadingHTTPServer(("127.0.0.1", args.port), EchoHandler)
    print(f"echo upstream on http://127.0.0.1:{args.port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
