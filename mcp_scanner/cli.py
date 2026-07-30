from __future__ import annotations

import argparse
import json
import sys

from .scanner import (
    DEFAULT_MAX_HOSTS,
    DEFAULT_PATHS,
    DEFAULT_PORTS,
    ScannerConfig,
    normalize_paths,
    parse_ports,
    scan,
)


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        ports = parse_ports(args.ports)
        paths = normalize_paths(args.paths)
        config = ScannerConfig(
            targets=args.targets,
            ports=ports,
            paths=paths,
            scheme=args.scheme,
            timeout=args.timeout,
            workers=args.workers,
            verify_tls=args.verify_tls,
            max_hosts=args.max_hosts,
            debug=args.debug,
        )
        findings = scan(config)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("scan interrupted", file=sys.stderr)
        return 130

    if args.json:
        print(json.dumps([finding.to_dict() for finding in findings], indent=2))
    else:
        print(format_findings(findings))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-scan",
        description="Discover HTTP-exposed MCP servers and list their tools.",
    )
    parser.add_argument(
        "targets",
        nargs="+",
        help="IP, CIDR, hostname, or comma-separated list of targets.",
    )
    parser.add_argument(
        "-p",
        "--ports",
        default=",".join(str(port) for port in DEFAULT_PORTS),
        help="Comma-separated ports and ranges. Default: common MCP/web dev ports.",
    )
    parser.add_argument(
        "--paths",
        default=",".join(DEFAULT_PATHS),
        help="Comma-separated HTTP paths to probe. Default: /mcp,/sse,/,/health.",
    )
    parser.add_argument(
        "--scheme",
        choices=("auto", "http", "https", "both"),
        default="auto",
        help="HTTP scheme mode. auto uses HTTPS for 443/8443 and HTTP otherwise.",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=float,
        default=1.5,
        help="Per-connection timeout in seconds.",
    )
    parser.add_argument(
        "-w",
        "--workers",
        type=int,
        default=64,
        help="Maximum concurrent host:port scans.",
    )
    parser.add_argument(
        "--max-hosts",
        type=int,
        default=DEFAULT_MAX_HOSTS,
        help="Safety cap for CIDR expansion.",
    )
    parser.add_argument(
        "--verify-tls",
        action="store_true",
        help="Verify TLS certificates. Disabled by default for internal scans.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit machine-readable JSON.",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Print probe diagnostics to stderr.",
    )
    return parser


def format_findings(findings) -> str:
    if not findings:
        return "No MCP servers or recognized MCP backends found."

    lines: list[str] = []
    for finding in findings:
        server_label = _server_label(finding.server_info)
        version = f" protocol={finding.protocol_version}" if finding.protocol_version else ""
        lines.append(
            f"[+] {finding.url} transport={finding.transport}{version}{server_label}"
        )
        if finding.capabilities:
            lines.append(f"    capabilities: {', '.join(sorted(finding.capabilities))}")
        if finding.tools:
            lines.append(f"    tools ({len(finding.tools)}):")
            for tool in finding.tools:
                suffix = f" - {tool.description}" if tool.description else ""
                title = f" ({tool.title})" if tool.title else ""
                lines.append(f"      - {tool.name}{title}{suffix}")
        else:
            lines.append("    tools: none listed")
        for note in finding.notes:
            lines.append(f"    note: {note}")
    return "\n".join(lines)


def _server_label(server_info) -> str:
    if not isinstance(server_info, dict):
        return ""
    name = server_info.get("name")
    version = server_info.get("version")
    if isinstance(name, str) and isinstance(version, str):
        return f" server={name}/{version}"
    if isinstance(name, str):
        return f" server={name}"
    return ""
