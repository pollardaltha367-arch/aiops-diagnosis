"""Dependency-free local web server for the AIOps diagnosis PoC."""

from __future__ import annotations

import json
import sys
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "assets" / "web"
sys.path.insert(0, str(Path(__file__).parent))

from diagnosis_engine import append_audit, diagnose, to_markdown  # noqa: E402


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(STATIC), **kwargs)

    def _json(self, payload: dict, status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/api/health":
            self._json({"status": "ok", "service": "aiops-diagnosis-poc"})
            return
        super().do_GET()

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/diagnose":
            self._json({"error": "not_found"}, 404)
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 2_000_000:
                raise ValueError("输入必须在 1 字节到 2 MB 之间")
            payload = json.loads(self.rfile.read(length).decode("utf-8"))
            text = str(payload.get("text", "")).strip()
            source = str(payload.get("source", "pasted.log"))[:120]
            if not text:
                raise ValueError("日志内容不能为空")
            report = diagnose(text, source)
            append_audit(ROOT / "data" / "audit.jsonl", report)
            self._json({"report": report, "markdown": to_markdown(report)})
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError) as exc:
            self._json({"error": "invalid_input", "message": str(exc)}, 400)
        except Exception:
            self._json({"error": "internal_error", "message": "诊断失败，请检查服务器日志。"}, 500)


def main() -> None:
    host, port = "127.0.0.1", 8765
    server = ThreadingHTTPServer((host, port), Handler)
    print(f"AIOps diagnosis PoC: http://{host}:{port}")
    print("Press Ctrl+C to stop.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
