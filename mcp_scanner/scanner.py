from __future__ import annotations

import concurrent.futures
import dataclasses
import ipaddress
import json
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable, Sequence
from typing import Any

CLIENT_NAME = "mcp-scanner"
CLIENT_VERSION = "0.1.0"

MODERN_VERSION = "2026-07-28"
LEGACY_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26")

DEFAULT_PORTS = (
    80,
    443,
    3000,
    3001,
    3333,
    5000,
    5173,
    6274,
    6277,
    8000,
    8008,
    8080,
    8081,
    8765,
    8888,
    9000,
    10000,
)
DEFAULT_PATHS = ("/mcp", "/sse", "/", "/health")
DEFAULT_MAX_HOSTS = 4096


@dataclasses.dataclass(frozen=True)
class Tool:
    name: str
    title: str | None = None
    description: str | None = None
    input_schema: dict[str, Any] | None = None
    output_schema: dict[str, Any] | None = None
    raw: dict[str, Any] | None = None

    @classmethod
    def from_mapping(cls, value: dict[str, Any]) -> "Tool | None":
        name = value.get("name")
        if not isinstance(name, str) or not name:
            return None
        input_schema = value.get("inputSchema")
        output_schema = value.get("outputSchema")
        return cls(
            name=name,
            title=_optional_str(value.get("title")),
            description=_optional_str(value.get("description")),
            input_schema=input_schema if isinstance(input_schema, dict) else None,
            output_schema=output_schema if isinstance(output_schema, dict) else None,
            raw=value,
        )

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {"name": self.name}
        if self.title:
            data["title"] = self.title
        if self.description:
            data["description"] = self.description
        if self.input_schema is not None:
            data["inputSchema"] = self.input_schema
        if self.output_schema is not None:
            data["outputSchema"] = self.output_schema
        return data


@dataclasses.dataclass(frozen=True)
class Finding:
    target: str
    host: str
    port: int
    scheme: str
    path: str
    url: str
    transport: str
    protocol_version: str | None = None
    server_info: dict[str, Any] | None = None
    capabilities: dict[str, Any] | None = None
    tools: tuple[Tool, ...] = ()
    notes: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "scheme": self.scheme,
            "path": self.path,
            "url": self.url,
            "transport": self.transport,
            "tool_count": len(self.tools),
            "tools": [tool.to_dict() for tool in self.tools],
        }
        if self.protocol_version:
            data["protocolVersion"] = self.protocol_version
        if self.server_info is not None:
            data["serverInfo"] = self.server_info
        if self.capabilities is not None:
            data["capabilities"] = self.capabilities
        if self.notes:
            data["notes"] = list(self.notes)
        return data


@dataclasses.dataclass(frozen=True)
class ScannerConfig:
    targets: Sequence[str]
    ports: Sequence[int] = DEFAULT_PORTS
    paths: Sequence[str] = DEFAULT_PATHS
    scheme: str = "auto"
    timeout: float = 1.5
    workers: int = 64
    verify_tls: bool = False
    max_hosts: int = DEFAULT_MAX_HOSTS
    debug: bool = False


@dataclasses.dataclass(frozen=True)
class HTTPResult:
    status: int
    headers: dict[str, str]
    body: str
    json_body: Any
    url: str
    error: str | None = None


class HTTPClient:
    def __init__(self, timeout: float, verify_tls: bool, max_body: int = 1024 * 1024):
        self.timeout = timeout
        self.max_body = max_body
        self._ssl_context = (
            ssl.create_default_context()
            if verify_tls
            else ssl._create_unverified_context()
        )

    def post_json(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> HTTPResult:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
            "User-Agent": f"{CLIENT_NAME}/{CLIENT_VERSION}",
        }
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(
            url,
            data=body,
            headers=request_headers,
            method="POST",
        )
        return self._open_request(request)

    def post_json_no_parse(
        self,
        url: str,
        payload: dict[str, Any],
        headers: dict[str, str] | None = None,
    ) -> HTTPResult:
        body = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        request_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "User-Agent": f"{CLIENT_NAME}/{CLIENT_VERSION}",
        }
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(
            url,
            data=body,
            headers=request_headers,
            method="POST",
        )
        return self._open_request(request, parse_sse=False)

    def get(self, url: str, headers: dict[str, str] | None = None) -> HTTPResult:
        request_headers = {
            "Accept": "application/json",
            "User-Agent": f"{CLIENT_NAME}/{CLIENT_VERSION}",
        }
        if headers:
            request_headers.update(headers)
        request = urllib.request.Request(url, headers=request_headers, method="GET")
        return self._open_request(request, parse_sse=False)

    def open_sse(self, url: str) -> tuple[Any | None, HTTPResult | None]:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "text/event-stream",
                "User-Agent": f"{CLIENT_NAME}/{CLIENT_VERSION}",
            },
            method="GET",
        )
        try:
            response = urllib.request.urlopen(
                request,
                timeout=self.timeout,
                context=self._ssl_context,
            )
        except urllib.error.HTTPError as exc:
            result = self._result_from_http_error(exc)
            return None, result
        except (OSError, TimeoutError, urllib.error.URLError, ssl.SSLError) as exc:
            return None, HTTPResult(0, {}, "", None, url, str(exc))

        headers = _headers_to_dict(response.headers.items())
        if response.status != 200 or "text/event-stream" not in headers.get(
            "content-type", ""
        ).lower():
            body = self._read_text_body(response)
            response.close()
            return (
                None,
                HTTPResult(response.status, headers, body, _loads_json(body), url),
            )
        return response, None

    def _open_request(
        self,
        request: urllib.request.Request,
        parse_sse: bool = True,
    ) -> HTTPResult:
        try:
            response = urllib.request.urlopen(
                request,
                timeout=self.timeout,
                context=self._ssl_context,
            )
        except urllib.error.HTTPError as exc:
            return self._result_from_http_error(exc)
        except (OSError, TimeoutError, urllib.error.URLError, ssl.SSLError) as exc:
            return HTTPResult(0, {}, "", None, request.full_url, str(exc))

        headers = _headers_to_dict(response.headers.items())
        content_type = headers.get("content-type", "").lower()
        if parse_sse and "text/event-stream" in content_type:
            body = self._read_sse_json_body(response)
        else:
            body = self._read_text_body(response)
        response.close()
        return HTTPResult(
            response.status,
            headers,
            body,
            _loads_json(body),
            response.url,
        )

    def _result_from_http_error(self, exc: urllib.error.HTTPError) -> HTTPResult:
        headers = _headers_to_dict(exc.headers.items())
        body = self._read_text_body(exc)
        return HTTPResult(exc.code, headers, body, _loads_json(body), exc.url)

    def _read_text_body(self, response: Any) -> str:
        try:
            raw = response.read(self.max_body + 1)
        except (OSError, TimeoutError, socket.timeout):
            return ""
        if len(raw) > self.max_body:
            raw = raw[: self.max_body]
        return raw.decode("utf-8", "replace")

    def _read_sse_json_body(self, response: Any) -> str:
        deadline = time.monotonic() + self.timeout
        while time.monotonic() < deadline:
            event = read_sse_event(response)
            if event is None:
                break
            _, data = event
            if _loads_json(data) is not None:
                return data
        return ""


def parse_ports(value: str | Sequence[int]) -> list[int]:
    if isinstance(value, str):
        parts = [part.strip() for part in value.split(",") if part.strip()]
        ports: list[int] = []
        for part in parts:
            if "-" in part:
                start_s, end_s = part.split("-", 1)
                start = _parse_port(start_s)
                end = _parse_port(end_s)
                if start > end:
                    raise ValueError(f"invalid port range: {part}")
                ports.extend(range(start, end + 1))
            else:
                ports.append(_parse_port(part))
    else:
        ports = [_parse_port(str(port)) for port in value]

    return sorted(set(ports))


def normalize_paths(value: str | Iterable[str]) -> list[str]:
    if isinstance(value, str):
        raw_paths = [part.strip() for part in value.split(",") if part.strip()]
    else:
        raw_paths = [str(part).strip() for part in value if str(part).strip()]

    paths: list[str] = []
    for path in raw_paths:
        normalized = path if path.startswith("/") else f"/{path}"
        if normalized not in paths:
            paths.append(normalized)
    if not paths:
        raise ValueError("at least one HTTP path is required")
    return paths


def expand_targets(values: Iterable[str], max_hosts: int = DEFAULT_MAX_HOSTS) -> list[str]:
    targets: list[str] = []
    for value in values:
        for item in [part.strip() for part in value.split(",") if part.strip()]:
            if "/" in item:
                try:
                    network = ipaddress.ip_network(item, strict=False)
                except ValueError:
                    targets.append(item)
                    continue
                hosts = [str(host) for host in network.hosts()]
                if network.num_addresses == 1:
                    hosts = [str(network.network_address)]
                if len(hosts) > max_hosts:
                    raise ValueError(
                        f"target {item} expands to {len(hosts)} hosts; "
                        f"raise --max-hosts to allow it"
                    )
                targets.extend(hosts)
                continue

            targets.append(item)

    deduped: list[str] = []
    seen: set[str] = set()
    for target in targets:
        if target not in seen:
            seen.add(target)
            deduped.append(target)
    if not deduped:
        raise ValueError("at least one target is required")
    return deduped


def scan(config: ScannerConfig) -> list[Finding]:
    targets = expand_targets(config.targets, max_hosts=config.max_hosts)
    ports = parse_ports(config.ports)
    paths = normalize_paths(config.paths)
    workers = max(1, int(config.workers))

    jobs = [(target, port) for target in targets for port in ports]
    findings: list[Finding] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        future_map = {
            executor.submit(_scan_host_port, target, port, paths, config): (target, port)
            for target, port in jobs
        }
        for future in concurrent.futures.as_completed(future_map):
            findings.extend(future.result())

    return sorted(findings, key=lambda item: (item.host, item.port, item.path))


def _scan_host_port(
    target: str,
    port: int,
    paths: Sequence[str],
    config: ScannerConfig,
) -> list[Finding]:
    saw_open_port = False
    for probe_host in _probe_hosts_for_target(target):
        if not _tcp_open(probe_host, port, config.timeout):
            _debug(config, f"{probe_host}:{port} tcp closed or timed out")
            continue

        saw_open_port = True
        _debug(config, f"{probe_host}:{port} tcp open")
        findings: list[Finding] = []
        client = HTTPClient(timeout=config.timeout, verify_tls=config.verify_tls)
        for scheme in _schemes_for_port(port, config.scheme):
            for path in paths:
                url = _build_url(scheme, probe_host, port, path)
                _debug(config, f"probing {url}")
                finding = _probe_endpoint(
                    client=client,
                    config=config,
                    target=target,
                    host=probe_host,
                    port=port,
                    scheme=scheme,
                    path=path,
                    url=url,
                )
                if finding is not None:
                    _debug(config, f"matched {url} as {finding.transport}")
                    findings.append(finding)
        if findings:
            return findings
        _debug(config, f"{probe_host}:{port} open but no MCP/backend match")
    if not saw_open_port:
        _debug(config, f"{target}:{port} no reachable loopback/address candidate")
    return []


def _probe_endpoint(
    client: HTTPClient,
    config: ScannerConfig,
    target: str,
    host: str,
    port: int,
    scheme: str,
    path: str,
    url: str,
) -> Finding | None:
    if _is_health_path(path):
        return _probe_health(client, config, target, host, port, scheme, path, url)

    modern = _probe_modern(client, target, host, port, scheme, path, url)
    if modern is not None:
        return modern

    legacy = _probe_legacy_streamable(client, target, host, port, scheme, path, url)
    if legacy is not None:
        return legacy

    return _probe_legacy_sse(client, target, host, port, scheme, path, url)


def _probe_health(
    client: HTTPClient,
    config: ScannerConfig,
    target: str,
    host: str,
    port: int,
    scheme: str,
    path: str,
    url: str,
) -> Finding | None:
    response = client.get(url)
    _debug(
        config,
        "health response "
        f"status={response.status} "
        f"content-type={response.headers.get('content-type', '')!r} "
        f"body={_body_snippet(response.body)!r}",
    )
    data = response.json_body
    if isinstance(data, dict) and _looks_like_hexstrike_health(data):
        return _finding_from_hexstrike_health(
            target=target,
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            url=url,
            health=data,
        )
    if isinstance(data, dict) and _looks_like_known_mcp_backend_health(data, port):
        return _finding_from_known_backend_health(
            target=target,
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            url=url,
            health=data,
        )
    if 200 <= response.status < 300 and _looks_like_hexstrike_text_health(
        response.body, port
    ):
        return _finding_from_possible_hexstrike_health(
            target=target,
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            url=url,
            response=response,
        )
    return None


def _probe_modern(
    client: HTTPClient,
    target: str,
    host: str,
    port: int,
    scheme: str,
    path: str,
    url: str,
) -> Finding | None:
    discover = _modern_payload("server/discover", "discover-1", MODERN_VERSION)
    response = client.post_json(
        url,
        discover,
        headers=_modern_headers("server/discover", MODERN_VERSION),
    )

    data = response.json_body
    if not isinstance(data, dict):
        return None

    version = MODERN_VERSION
    server_info: dict[str, Any] | None = None
    capabilities: dict[str, Any] | None = None
    notes: list[str] = []

    if _is_jsonrpc_result(data):
        result = data["result"]
        if not isinstance(result, dict):
            return None
        supported = result.get("supportedVersions")
        if isinstance(supported, list) and supported:
            version = _choose_version(supported, MODERN_VERSION)
        capabilities = result.get("capabilities") if isinstance(result.get("capabilities"), dict) else None
        server_info = _extract_modern_server_info(result)
    elif _is_unsupported_protocol_error(data):
        supported = data["error"].get("data", {}).get("supported", [])
        if isinstance(supported, list) and supported:
            version = _choose_version(supported, MODERN_VERSION)
            notes.append("server returned UnsupportedProtocolVersion during discovery")
        else:
            return None
    elif _is_header_mismatch_error(data):
        notes.append("server returned MCP header mismatch during discovery")
    else:
        return None

    tools, tool_note = _list_modern_tools(client, url, version)
    if tool_note:
        notes.append(tool_note)
    return Finding(
        target=target,
        host=host,
        port=port,
        scheme=scheme,
        path=path,
        url=url,
        transport="streamable-http-modern",
        protocol_version=version,
        server_info=server_info,
        capabilities=capabilities,
        tools=tuple(tools),
        notes=tuple(notes),
    )


def _finding_from_hexstrike_health(
    target: str,
    host: str,
    port: int,
    scheme: str,
    path: str,
    url: str,
    health: dict[str, Any],
) -> Finding:
    tools_status = health.get("tools_status")
    tools = _tools_from_hexstrike_status(tools_status if isinstance(tools_status, dict) else {})
    version = _optional_str(health.get("version"))
    capabilities = {
        "hexstrike": {
            "total_tools_count": health.get("total_tools_count"),
            "total_tools_available": health.get("total_tools_available"),
            "all_essential_tools_available": health.get("all_essential_tools_available"),
            "category_stats": health.get("category_stats"),
        }
    }
    server_info = {"name": "hexstrike-ai"}
    if version:
        server_info["version"] = version
    return Finding(
        target=target,
        host=host,
        port=port,
        scheme=scheme,
        path=path,
        url=url,
        transport="hexstrike-rest-backend",
        server_info=server_info,
        capabilities=capabilities,
        tools=tuple(tools),
        notes=(
            "HexStrike /health is a REST API backend used by the hexstrike_mcp.py stdio bridge; it is not a direct Streamable HTTP MCP endpoint.",
            "Tools are derived from health.tools_status, not from MCP tools/list.",
        ),
    )


def _finding_from_known_backend_health(
    target: str,
    host: str,
    port: int,
    scheme: str,
    path: str,
    url: str,
    health: dict[str, Any],
) -> Finding:
    server_info = _server_info_from_health(health)
    capabilities = {"health": _compact_health_capabilities(health)}
    notes = [
        "Health endpoint matched a known MCP-adjacent backend pattern, but did not expose MCP tools/list.",
    ]
    if port == 8888:
        server_info.setdefault("name", "hexstrike-ai")
        notes.append(
            "Port 8888 is the default HexStrike REST backend used by the hexstrike_mcp.py stdio bridge."
        )
    return Finding(
        target=target,
        host=host,
        port=port,
        scheme=scheme,
        path=path,
        url=url,
        transport="mcp-adjacent-health-backend",
        server_info=server_info,
        capabilities=capabilities,
        tools=(),
        notes=tuple(notes),
    )


def _finding_from_possible_hexstrike_health(
    target: str,
    host: str,
    port: int,
    scheme: str,
    path: str,
    url: str,
    response: HTTPResult,
) -> Finding:
    return Finding(
        target=target,
        host=host,
        port=port,
        scheme=scheme,
        path=path,
        url=url,
        transport="possible-hexstrike-rest-backend",
        server_info={"name": "hexstrike-ai"},
        capabilities={
            "health": {
                "http_status": response.status,
                "content_type": response.headers.get("content-type", ""),
            }
        },
        tools=(),
        notes=(
            "Port 8888 /health returned HTTP 2xx, which matches the default HexStrike REST backend location.",
            "The health response did not expose tools_status, so tool names could not be derived.",
            "This is a low-confidence backend fingerprint, not a direct Streamable HTTP MCP endpoint.",
        ),
    )


def _tools_from_hexstrike_status(tools_status: dict[str, Any]) -> list[Tool]:
    tools: list[Tool] = []
    for name in sorted(tools_status):
        available = bool(tools_status[name])
        description = (
            "available on HexStrike backend"
            if available
            else "missing on HexStrike backend"
        )
        tools.append(
            Tool(
                name=name,
                description=description,
                raw={"available": available},
            )
        )
    return tools


def _probe_legacy_streamable(
    client: HTTPClient,
    target: str,
    host: str,
    port: int,
    scheme: str,
    path: str,
    url: str,
) -> Finding | None:
    for requested_version in LEGACY_VERSIONS:
        init = {
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": requested_version,
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
            },
        }
        response = client.post_json(url, init)
        data = response.json_body
        if not _is_jsonrpc_result(data):
            continue

        result = data["result"]
        if not isinstance(result, dict):
            continue
        protocol_version = _optional_str(result.get("protocolVersion")) or requested_version
        capabilities = (
            result.get("capabilities") if isinstance(result.get("capabilities"), dict) else None
        )
        server_info = (
            result.get("serverInfo") if isinstance(result.get("serverInfo"), dict) else None
        )
        session_id = response.headers.get("mcp-session-id")

        legacy_headers: dict[str, str] = {"MCP-Protocol-Version": protocol_version}
        if session_id:
            legacy_headers["Mcp-Session-Id"] = session_id

        initialized = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        client.post_json_no_parse(url, initialized, headers=legacy_headers)

        tools, note = _list_legacy_tools(client, url, protocol_version, session_id)
        notes = (note,) if note else ()
        return Finding(
            target=target,
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            url=url,
            transport="streamable-http-legacy",
            protocol_version=protocol_version,
            server_info=server_info,
            capabilities=capabilities,
            tools=tuple(tools),
            notes=notes,
        )
    return None


def _probe_legacy_sse(
    client: HTTPClient,
    target: str,
    host: str,
    port: int,
    scheme: str,
    path: str,
    url: str,
) -> Finding | None:
    response, error_result = client.open_sse(url)
    if response is None:
        return None

    try:
        endpoint_url = _read_legacy_sse_endpoint(response, url)
        if endpoint_url is None:
            return None

        init = {
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": CLIENT_NAME, "version": CLIENT_VERSION},
            },
        }
        client.post_json_no_parse(endpoint_url, init)
        init_response = _read_sse_json_response(response, "init-1", client.timeout)
        if not _is_jsonrpc_result(init_response):
            return Finding(
                target=target,
                host=host,
                port=port,
                scheme=scheme,
                path=path,
                url=url,
                transport="http+sse-legacy",
                protocol_version="2024-11-05",
                tools=(),
                notes=("SSE endpoint detected but initialize response was not readable",),
            )

        result = init_response["result"]
        protocol_version = (
            _optional_str(result.get("protocolVersion"))
            if isinstance(result, dict)
            else None
        ) or "2024-11-05"
        capabilities = (
            result.get("capabilities")
            if isinstance(result, dict) and isinstance(result.get("capabilities"), dict)
            else None
        )
        server_info = (
            result.get("serverInfo")
            if isinstance(result, dict) and isinstance(result.get("serverInfo"), dict)
            else None
        )

        client.post_json_no_parse(
            endpoint_url,
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
        )
        tools, note = _list_legacy_sse_tools(client, response, endpoint_url)
        notes = (note,) if note else ()
        return Finding(
            target=target,
            host=host,
            port=port,
            scheme=scheme,
            path=path,
            url=url,
            transport="http+sse-legacy",
            protocol_version=protocol_version,
            server_info=server_info,
            capabilities=capabilities,
            tools=tuple(tools),
            notes=notes,
        )
    finally:
        response.close()


def _list_modern_tools(
    client: HTTPClient,
    url: str,
    version: str,
    max_pages: int = 20,
) -> tuple[list[Tool], str | None]:
    tools: list[Tool] = []
    cursor: str | None = None
    for page in range(max_pages):
        params: dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        payload = _modern_payload("tools/list", f"tools-{page + 1}", version, params)
        response = client.post_json(
            url,
            payload,
            headers=_modern_headers("tools/list", version),
        )
        data = response.json_body
        if _jsonrpc_error_code(data) == -32601:
            return tools, "server does not implement tools/list"
        if not _is_jsonrpc_result(data):
            return tools, f"tools/list failed with HTTP status {response.status}"
        result = data["result"]
        if not isinstance(result, dict):
            return tools, "tools/list returned an invalid result"
        tools.extend(_extract_tools(result))
        next_cursor = result.get("nextCursor")
        if not isinstance(next_cursor, str) or not next_cursor:
            return tools, None
        cursor = next_cursor
    return tools, f"tools/list stopped after {max_pages} pages"


def _list_legacy_tools(
    client: HTTPClient,
    url: str,
    protocol_version: str,
    session_id: str | None,
    max_pages: int = 20,
) -> tuple[list[Tool], str | None]:
    headers: dict[str, str] = {"MCP-Protocol-Version": protocol_version}
    if session_id:
        headers["Mcp-Session-Id"] = session_id

    tools: list[Tool] = []
    cursor: str | None = None
    for page in range(max_pages):
        params: dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        response = client.post_json(
            url,
            {
                "jsonrpc": "2.0",
                "id": f"tools-{page + 1}",
                "method": "tools/list",
                "params": params,
            },
            headers=headers,
        )
        data = response.json_body
        if _jsonrpc_error_code(data) == -32601:
            return tools, "server does not implement tools/list"
        if not _is_jsonrpc_result(data):
            return tools, f"tools/list failed with HTTP status {response.status}"
        result = data["result"]
        if not isinstance(result, dict):
            return tools, "tools/list returned an invalid result"
        tools.extend(_extract_tools(result))
        next_cursor = result.get("nextCursor")
        if not isinstance(next_cursor, str) or not next_cursor:
            return tools, None
        cursor = next_cursor
    return tools, f"tools/list stopped after {max_pages} pages"


def _list_legacy_sse_tools(
    client: HTTPClient,
    response: Any,
    endpoint_url: str,
    max_pages: int = 20,
) -> tuple[list[Tool], str | None]:
    tools: list[Tool] = []
    cursor: str | None = None
    for page in range(max_pages):
        params: dict[str, Any] = {}
        if cursor:
            params["cursor"] = cursor
        request_id = f"tools-{page + 1}"
        client.post_json_no_parse(
            endpoint_url,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/list",
                "params": params,
            },
        )
        data = _read_sse_json_response(response, request_id, client.timeout)
        if _jsonrpc_error_code(data) == -32601:
            return tools, "server does not implement tools/list"
        if not _is_jsonrpc_result(data):
            return tools, "tools/list response was not readable from SSE stream"
        result = data["result"]
        if not isinstance(result, dict):
            return tools, "tools/list returned an invalid result"
        tools.extend(_extract_tools(result))
        next_cursor = result.get("nextCursor")
        if not isinstance(next_cursor, str) or not next_cursor:
            return tools, None
        cursor = next_cursor
    return tools, f"tools/list stopped after {max_pages} pages"


def read_sse_event(response: Any) -> tuple[str, str] | None:
    event_name = "message"
    data_lines: list[str] = []
    while True:
        try:
            raw_line = response.readline(65536)
        except (OSError, TimeoutError, socket.timeout):
            return None
        if not raw_line:
            return None
        line = raw_line.decode("utf-8", "replace")
        stripped = line.rstrip("\r\n")
        if not stripped:
            if data_lines:
                return event_name, "\n".join(data_lines)
            event_name = "message"
            data_lines = []
            continue
        if stripped.startswith(":"):
            continue
        field, separator, value = stripped.partition(":")
        if separator and value.startswith(" "):
            value = value[1:]
        if field == "event":
            event_name = value
        elif field == "data":
            data_lines.append(value)


def _read_legacy_sse_endpoint(response: Any, base_url: str) -> str | None:
    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline:
        event = read_sse_event(response)
        if event is None:
            return None
        event_name, data = event
        if event_name == "endpoint" and data:
            return _safe_sse_endpoint_url(base_url, data)
    return None


def _safe_sse_endpoint_url(base_url: str, endpoint: str) -> str | None:
    endpoint = endpoint.strip()
    if not endpoint or any(ord(char) < 32 or ord(char) == 127 for char in endpoint):
        return None

    candidate = urllib.parse.urljoin(base_url, endpoint)
    try:
        base = urllib.parse.urlsplit(base_url)
        parsed = urllib.parse.urlsplit(candidate)
        base_origin = _url_origin(base)
        parsed_origin = _url_origin(parsed)
    except ValueError:
        return None

    if parsed.scheme not in {"http", "https"}:
        return None
    if parsed.username or parsed.password:
        return None
    if base_origin != parsed_origin:
        return None

    return urllib.parse.urlunsplit(parsed)


def _url_origin(parts: urllib.parse.SplitResult) -> tuple[str, str, int | None]:
    port = parts.port
    if port is None:
        if parts.scheme == "http":
            port = 80
        elif parts.scheme == "https":
            port = 443
    hostname = (parts.hostname or "").lower()
    return parts.scheme.lower(), hostname, port


def _read_sse_json_response(response: Any, request_id: str, timeout: float) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        event = read_sse_event(response)
        if event is None:
            return None
        _, data = event
        parsed = _loads_json(data)
        if isinstance(parsed, dict) and parsed.get("id") == request_id:
            return parsed
    return None


def _modern_payload(
    method: str,
    request_id: str,
    version: str,
    params: dict[str, Any] | None = None,
) -> dict[str, Any]:
    payload_params = dict(params or {})
    payload_params["_meta"] = {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": {
            "name": CLIENT_NAME,
            "version": CLIENT_VERSION,
        },
        "io.modelcontextprotocol/clientCapabilities": {},
    }
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": method,
        "params": payload_params,
    }


def _modern_headers(method: str, version: str) -> dict[str, str]:
    return {
        "MCP-Protocol-Version": version,
        "Mcp-Method": method,
    }


def _extract_tools(result: dict[str, Any]) -> list[Tool]:
    raw_tools = result.get("tools")
    if not isinstance(raw_tools, list):
        return []
    tools: list[Tool] = []
    for raw_tool in raw_tools:
        if isinstance(raw_tool, dict):
            tool = Tool.from_mapping(raw_tool)
            if tool is not None:
                tools.append(tool)
    return tools


def _extract_modern_server_info(result: dict[str, Any]) -> dict[str, Any] | None:
    meta = result.get("_meta")
    if not isinstance(meta, dict):
        return None
    server_info = meta.get("io.modelcontextprotocol/serverInfo")
    return server_info if isinstance(server_info, dict) else None


def _is_jsonrpc_result(data: Any) -> bool:
    return isinstance(data, dict) and data.get("jsonrpc") == "2.0" and "result" in data


def _jsonrpc_error_code(data: Any) -> int | None:
    if not isinstance(data, dict):
        return None
    error = data.get("error")
    if not isinstance(error, dict):
        return None
    code = error.get("code")
    return code if isinstance(code, int) else None


def _is_unsupported_protocol_error(data: Any) -> bool:
    return _jsonrpc_error_code(data) == -32022


def _is_header_mismatch_error(data: Any) -> bool:
    return _jsonrpc_error_code(data) == -32020


def _is_health_path(path: str) -> bool:
    return path.rstrip("/").lower() == "/health"


def _looks_like_hexstrike_health(data: dict[str, Any]) -> bool:
    haystack = " ".join(str(data.get(key, "")) for key in ("message", "name", "service"))
    has_hexstrike_message = "hexstrike" in haystack.lower()
    has_hexstrike_shape = (
        isinstance(data.get("tools_status"), dict)
        and "total_tools_count" in data
        and "category_stats" in data
    )
    return has_hexstrike_message or has_hexstrike_shape


def _looks_like_known_mcp_backend_health(data: dict[str, Any], port: int) -> bool:
    status = str(data.get("status", "")).lower()
    if status not in {"ok", "healthy", "ready", "running"}:
        return False
    if port == 8888:
        return True
    haystack = " ".join(str(data.get(key, "")) for key in ("message", "name", "service"))
    return "mcp" in haystack.lower()


def _looks_like_hexstrike_text_health(body: str, port: int) -> bool:
    normalized = body.strip().lower()
    if not normalized:
        return False
    if "hexstrike" in normalized:
        return True
    return port == 8888


def _server_info_from_health(health: dict[str, Any]) -> dict[str, Any]:
    server_info: dict[str, Any] = {}
    for source_key, target_key in (
        ("name", "name"),
        ("service", "name"),
        ("version", "version"),
    ):
        value = _optional_str(health.get(source_key))
        if value and target_key not in server_info:
            server_info[target_key] = value
    return server_info


def _compact_health_capabilities(health: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "status",
        "version",
        "total_tools_count",
        "total_tools_available",
        "all_essential_tools_available",
        "category_stats",
    }
    return {key: value for key, value in health.items() if key in allowed}


def _choose_version(supported: Sequence[Any], preferred: str) -> str:
    string_versions = [item for item in supported if isinstance(item, str)]
    if preferred in string_versions:
        return preferred
    modern_versions = [item for item in string_versions if item >= "2026-07-28"]
    if modern_versions:
        return sorted(modern_versions, reverse=True)[0]
    return string_versions[0] if string_versions else preferred


def _schemes_for_port(port: int, scheme: str) -> tuple[str, ...]:
    if scheme == "http":
        return ("http",)
    if scheme == "https":
        return ("https",)
    if scheme == "both":
        return ("http", "https")
    if scheme != "auto":
        raise ValueError(f"invalid scheme mode: {scheme}")
    return ("https",) if port in {443, 8443} else ("http",)


def _build_url(scheme: str, host: str, port: int, path: str) -> str:
    url_host = _format_host_for_url(host)
    quoted_path = urllib.parse.quote(path, safe="/~!$&'()*+,;=:@")
    return f"{scheme}://{url_host}:{port}{quoted_path}"


def _format_host_for_url(host: str) -> str:
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if address.version == 6:
        return f"[{host}]"
    return host


def _probe_hosts_for_target(target: str) -> tuple[str, ...]:
    if target.lower() != "localhost":
        return (target,)
    return ("localhost", "127.0.0.1", "::1")


def _tcp_open(host: str, port: int, timeout: float) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid port: {value}") from exc
    if not 1 <= port <= 65535:
        raise ValueError(f"port out of range: {value}")
    return port


def _headers_to_dict(items: Iterable[tuple[str, str]]) -> dict[str, str]:
    return {key.lower(): value for key, value in items}


def _loads_json(value: str) -> Any:
    if not value:
        return None
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return None


def _optional_str(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _debug(config: ScannerConfig, message: str) -> None:
    if config.debug:
        print(f"[debug] {message}", file=sys.stderr)


def _body_snippet(body: str, limit: int = 160) -> str:
    compact = " ".join(body.split())
    if len(compact) <= limit:
        return compact
    return f"{compact[:limit]}..."
