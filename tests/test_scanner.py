from __future__ import annotations

import json
import shutil
import subprocess
import threading
import unittest
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from mcp_scanner.scanner import (
    ScannerConfig,
    _looks_like_known_mcp_backend_health,
    expand_targets,
    parse_ports,
    scan,
)


class _BaseHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002
        return

    def _read_json(self):
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8")
        return json.loads(body) if body else {}

    def _send_json(self, status, payload, extra_headers=None):
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for key, value in (extra_headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)


class ModernMCPHandler(_BaseHandler):
    def do_POST(self):  # noqa: N802
        data = self._read_json()
        if self.path != "/mcp":
            self._send_json(404, {"error": "not found"})
            return

        if data.get("method") == "server/discover":
            self._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": data.get("id"),
                    "result": {
                        "resultType": "complete",
                        "supportedVersions": ["2026-07-28"],
                        "capabilities": {"tools": {}},
                        "_meta": {
                            "io.modelcontextprotocol/serverInfo": {
                                "name": "modern-test",
                                "version": "1.0",
                            }
                        },
                    },
                },
            )
            return

        if data.get("method") == "tools/list":
            self._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": data.get("id"),
                    "result": {
                        "resultType": "complete",
                        "tools": [
                            {
                                "name": "search",
                                "title": "Search",
                                "description": "Search indexed content",
                                "inputSchema": {"type": "object"},
                            }
                        ],
                    },
                },
            )
            return

        self._send_json(
            200,
            {
                "jsonrpc": "2.0",
                "id": data.get("id"),
                "error": {"code": -32601, "message": "method not found"},
            },
        )


class LegacyMCPHandler(_BaseHandler):
    def do_POST(self):  # noqa: N802
        data = self._read_json()
        if self.path != "/mcp":
            self._send_json(404, {"error": "not found"})
            return

        if data.get("method") == "initialize":
            self._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": data.get("id"),
                    "result": {
                        "protocolVersion": "2025-06-18",
                        "capabilities": {"tools": {"listChanged": False}},
                        "serverInfo": {"name": "legacy-test", "version": "1.0"},
                    },
                },
                {"Mcp-Session-Id": "test-session"},
            )
            return

        if data.get("method") == "notifications/initialized":
            self._send_json(202, {})
            return

        if data.get("method") == "tools/list":
            if self.headers.get("Mcp-Session-Id") != "test-session":
                self._send_json(
                    400,
                    {
                        "jsonrpc": "2.0",
                        "id": data.get("id"),
                        "error": {"code": -32000, "message": "missing session"},
                    },
                )
                return
            self._send_json(
                200,
                {
                    "jsonrpc": "2.0",
                    "id": data.get("id"),
                    "result": {
                        "tools": [
                            {
                                "name": "fetch",
                                "description": "Fetch a resource",
                                "inputSchema": {"type": "object"},
                            }
                        ]
                    },
                },
            )
            return

        self._send_json(404, {"error": "not found"})


class HexStrikeHealthHandler(_BaseHandler):
    def do_GET(self):  # noqa: N802
        if self.path != "/health":
            self._send_json(404, {"error": "not found"})
            return
        self._send_json(
            200,
            {
                "status": "healthy",
                "message": "HexStrike AI Tools API Server is operational",
                "version": "6.0.0",
                "tools_status": {
                    "nmap": True,
                    "masscan": False,
                    "sqlmap": True,
                },
                "all_essential_tools_available": False,
                "total_tools_available": 2,
                "total_tools_count": 3,
                "category_stats": {
                    "network": {"total": 2, "available": 1},
                    "web_security": {"total": 1, "available": 1},
                },
            },
        )

    def do_POST(self):  # noqa: N802
        self._send_json(405, {"error": "method not allowed"})


class MinimalHealthHandler(_BaseHandler):
    def do_GET(self):  # noqa: N802
        if self.path != "/health":
            self._send_json(404, {"error": "not found"})
            return
        self._send_json(200, {"status": "healthy"})

    def do_POST(self):  # noqa: N802
        self._send_json(405, {"error": "method not allowed"})


class TextHexStrikeHealthHandler(_BaseHandler):
    def do_GET(self):  # noqa: N802
        if self.path != "/health":
            self._send_json(404, {"error": "not found"})
            return
        body = b"HexStrike AI health ok"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        self._send_json(405, {"error": "method not allowed"})


class ChunkedSSEMCPHandler(_BaseHandler):
    session_id = "test-session"
    stream = None
    done = False
    condition = threading.Condition()

    @classmethod
    def reset(cls):
        with cls.condition:
            cls.stream = None
            cls.done = False

    def do_GET(self):  # noqa: N802
        if self.path != "/":
            self._send_json(404, {"error": "not found"})
            return

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "keep-alive")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

        with type(self).condition:
            type(self).stream = self.wfile
            type(self).condition.notify_all()
        type(self)._write_sse("endpoint", f"?sessionId={type(self).session_id}")

        with type(self).condition:
            while not type(self).done:
                type(self).condition.wait(timeout=0.1)
        try:
            self.wfile.write(b"0\r\n\r\n")
            self.wfile.flush()
        except OSError:
            return

    def do_POST(self):  # noqa: N802
        if self.path != f"/?sessionId={type(self).session_id}":
            self._send_json(400, {"error": "missing session"})
            return

        data = self._read_json()
        self.send_response(202)
        self.send_header("Content-Length", "0")
        self.end_headers()

        if data.get("method") == "initialize":
            type(self)._write_sse(
                "message",
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": data.get("id"),
                        "result": {
                            "protocolVersion": "2025-03-26",
                            "capabilities": {"tools": {}},
                            "serverInfo": {"name": "sse-test", "version": "1.0"},
                        },
                    }
                ),
            )
        elif data.get("method") == "tools/list":
            type(self)._write_sse(
                "message",
                json.dumps(
                    {
                        "jsonrpc": "2.0",
                        "id": data.get("id"),
                        "result": {
                            "tools": [
                                {
                                    "name": "demo_tool",
                                    "description": "Demo SSE tool",
                                }
                            ]
                        },
                    }
                ),
            )
            with type(self).condition:
                type(self).done = True
                type(self).condition.notify_all()

    @classmethod
    def _write_sse(cls, event, data):
        body = f"event: {event}\r\ndata: {data}\r\n\r\n".encode("utf-8")
        with cls.condition:
            if cls.stream is None:
                cls.condition.wait(timeout=2)
            stream = cls.stream
        if stream is None:
            return
        try:
            stream.write(f"{len(body):x}\r\n".encode("ascii"))
            stream.write(body)
            stream.write(b"\r\n")
            stream.flush()
        except OSError:
            return


class TrapPOSTHandler(_BaseHandler):
    posts = 0

    @classmethod
    def reset(cls):
        cls.posts = 0

    def do_POST(self):  # noqa: N802
        type(self).posts += 1
        self._send_json(202, {})


class OffOriginSSEEndpointHandler(_BaseHandler):
    endpoint = ""

    def do_GET(self):  # noqa: N802
        if self.path != "/":
            self._send_json(404, {"error": "not found"})
            return
        body = (
            f"event: endpoint\r\n"
            f"data: {type(self).endpoint}\r\n"
            f"\r\n"
        ).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):  # noqa: N802
        self._send_json(404, {"error": "not found"})


class ScannerTests(unittest.TestCase):
    def test_parse_ports_accepts_ranges(self):
        self.assertEqual(parse_ports("80,8000-8002,80"), [80, 8000, 8001, 8002])

    def test_expand_targets_accepts_cidr(self):
        self.assertEqual(expand_targets(["127.0.0.1/32"]), ["127.0.0.1"])

    def test_discovers_modern_mcp_and_lists_tools(self):
        with run_server(ModernMCPHandler) as port:
            findings = scan(
                ScannerConfig(
                    targets=["127.0.0.1"],
                    ports=[port],
                    paths=["/mcp"],
                    scheme="http",
                    timeout=1.0,
                    workers=4,
                )
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].transport, "streamable-http-modern")
        self.assertEqual(findings[0].tools[0].name, "search")

    def test_discovers_legacy_mcp_and_lists_tools(self):
        with run_server(LegacyMCPHandler) as port:
            findings = scan(
                ScannerConfig(
                    targets=["127.0.0.1"],
                    ports=[port],
                    paths=["/mcp"],
                    scheme="http",
                    timeout=1.0,
                    workers=4,
                )
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].transport, "streamable-http-legacy")
        self.assertEqual(findings[0].tools[0].name, "fetch")

    def test_detects_hexstrike_health_backend(self):
        with run_server(HexStrikeHealthHandler) as port:
            findings = scan(
                ScannerConfig(
                    targets=["127.0.0.1"],
                    ports=[port],
                    paths=["/health"],
                    scheme="http",
                    timeout=1.0,
                    workers=4,
                )
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].transport, "hexstrike-rest-backend")
        self.assertEqual(findings[0].server_info["name"], "hexstrike-ai")
        self.assertEqual(findings[0].server_info["version"], "6.0.0")
        self.assertEqual([tool.name for tool in findings[0].tools], ["masscan", "nmap", "sqlmap"])
        self.assertIn("stdio bridge", findings[0].notes[0])

    def test_detects_minimal_health_on_hexstrike_default_port(self):
        with run_server(MinimalHealthHandler) as port:
            findings = scan(
                ScannerConfig(
                    targets=["127.0.0.1"],
                    ports=[port],
                    paths=["/health"],
                    scheme="http",
                    timeout=1.0,
                    workers=4,
                )
            )

        self.assertEqual(findings, [])
        self.assertTrue(
            _looks_like_known_mcp_backend_health({"status": "healthy"}, 8888)
        )

    def test_detects_text_hexstrike_health(self):
        with run_server(TextHexStrikeHealthHandler) as port:
            findings = scan(
                ScannerConfig(
                    targets=["127.0.0.1"],
                    ports=[port],
                    paths=["/health"],
                    scheme="http",
                    timeout=1.0,
                    workers=4,
                )
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].transport, "possible-hexstrike-rest-backend")
        self.assertEqual(findings[0].server_info["name"], "hexstrike-ai")

    def test_localhost_falls_back_to_loopback_alias(self):
        with run_server(HexStrikeHealthHandler) as port:
            findings = scan(
                ScannerConfig(
                    targets=["localhost"],
                    ports=[port],
                    paths=["/health"],
                    scheme="http",
                    timeout=1.0,
                    workers=4,
                )
            )

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].target, "localhost")
        self.assertIn(findings[0].host, {"localhost", "127.0.0.1", "::1"})

    def test_rejects_off_origin_sse_endpoint(self):
        TrapPOSTHandler.reset()
        with run_server(TrapPOSTHandler) as trap_port:
            OffOriginSSEEndpointHandler.endpoint = (
                f"http://127.0.0.1:{trap_port}/messages"
            )
            with run_server(OffOriginSSEEndpointHandler) as port:
                findings = scan(
                    ScannerConfig(
                        targets=["127.0.0.1"],
                        ports=[port],
                        paths=["/"],
                        scheme="http",
                        timeout=1.0,
                        workers=4,
                    )
                )

        self.assertEqual(findings, [])
        self.assertEqual(TrapPOSTHandler.posts, 0)

    def test_nse_module_detects_hexstrike_health(self):
        if shutil.which("nmap") is None:
            self.skipTest("nmap is not installed")

        repo_root = Path(__file__).resolve().parents[1]
        with run_server(HexStrikeHealthHandler) as port:
            completed = subprocess.run(
                [
                    "nmap",
                    "-Pn",
                    "-p",
                    str(port),
                    "--script",
                    "./nse/mcp-info.nse",
                    "127.0.0.1",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=repo_root,
            )

        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, output)
        self.assertIn("mcp-info", output)
        self.assertIn("hexstrike-rest-backend", output)
        self.assertIn("sqlmap", output)

    def test_nse_module_lists_chunked_sse_tools(self):
        if shutil.which("nmap") is None:
            self.skipTest("nmap is not installed")

        ChunkedSSEMCPHandler.reset()
        repo_root = Path(__file__).resolve().parents[1]
        with run_server(ChunkedSSEMCPHandler) as port:
            completed = subprocess.run(
                [
                    "nmap",
                    "-Pn",
                    "-p",
                    str(port),
                    "--script",
                    "./nse/mcp-info.nse",
                    "--script-args",
                    "mcp-info.paths=/",
                    "127.0.0.1",
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
                cwd=repo_root,
            )

        output = completed.stdout + completed.stderr
        self.assertEqual(completed.returncode, 0, output)
        self.assertIn("http+sse-legacy", output)
        self.assertIn("sse-test/1.0", output)
        self.assertIn("demo_tool", output)


class run_server:
    def __init__(self, handler):
        self.handler = handler
        self.server = None
        self.thread = None

    def __enter__(self):
        self.server = QuietThreadingHTTPServer(("127.0.0.1", 0), self.handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        return self.server.server_address[1]

    def __exit__(self, exc_type, exc, tb):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class QuietThreadingHTTPServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):
        return


if __name__ == "__main__":
    unittest.main()
