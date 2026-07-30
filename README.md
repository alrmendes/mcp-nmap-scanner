# MCP Nmap Scanner

Nmap NSE module and small Python harness for discovering HTTP-exposed Model
Context Protocol (MCP) servers and listing their advertised tools.

The scanner is designed for inventory and exposure assessment. It only performs
MCP discovery and list operations. It does **not** execute MCP tools.

## Features

- Nmap NSE script for network scans: `nse/mcp-info.nse`.
- Detects modern Streamable HTTP MCP servers with `server/discover`.
- Detects legacy Streamable HTTP MCP servers with `initialize`.
- Detects legacy HTTP+SSE MCP servers, including chunked SSE streams and
  `sessionId` query-parameter endpoints.
- Lists advertised MCP tools with `tools/list`.
- Fingerprints HexStrike AI REST backends via `/health`.
- Optional Python CLI for local development and regression testing.

## Supported Transports

| Transport | Status |
| --- | --- |
| Streamable HTTP modern | Supported |
| Streamable HTTP legacy | Supported |
| HTTP+SSE legacy | Supported |
| HTTP+SSE with chunked encoding | Supported |
| HexStrike AI `/health` backend | Fingerprinted |
| stdio-only MCP servers | Not remotely scannable |

## Quick Start

Run the NSE script directly from this repository:

```bash
nmap -Pn -p 9876 --script ./nse/mcp-info.nse 127.0.0.1
```

For legacy HTTP+SSE servers exposed at `/`, explicitly limiting the path is
faster:

```bash
nmap -Pn -p 9876 --script ./nse/mcp-info.nse --script-args mcp-info.paths=/ 127.0.0.1
```

Scan common MCP and web development ports:

```bash
nmap -Pn -p 3000,3001,5173,6274,6277,8000,8008,8080,8081,8765,8888,9000,9876,10000 --script ./nse/mcp-info.nse <target>
```

Customize probe paths:

```bash
nmap -Pn -p 8000,8888 --script ./nse/mcp-info.nse --script-args mcp-info.paths=/mcp,/sse,/health <target>
```

## Installing the NSE Script

You can copy the script into Nmap's script directory and use it by name.

On many macOS/Linux installations:

```bash
sudo install -m 0644 nse/mcp-info.nse /usr/local/share/nmap/scripts/mcp-info.nse
sudo nmap --script-updatedb
nmap -Pn -p 9876 --script mcp-info 127.0.0.1
```

If your Nmap scripts directory is different, locate it with:

```bash
nmap --datadir
```

## NSE Script Arguments

| Argument | Description | Default |
| --- | --- | --- |
| `mcp-info.paths` | Comma-separated HTTP paths to probe | `/mcp,/sse,/,/health` |
| `mcp-info.max-pages` | Maximum `tools/list` pages to request | `20` |
| `mcp-info.modern-version` | MCP protocol version for `server/discover` | `2026-07-28` |

Example:

```bash
nmap -Pn -p 9876 --script ./nse/mcp-info.nse --script-args mcp-info.paths=/,mcp-info.max-pages=5 127.0.0.1
```

## Example Output

```text
PORT     STATE SERVICE
9876/tcp open  sd
| mcp-info:
|   url: http://127.0.0.1:9876/
|   transport: http+sse-legacy
|   protocol: 2025-03-26
|   server: burp-suite/1.1.2
|   tools:
|     send_http1_request: Issues an HTTP/1.1 request and returns the response.
|     send_http2_request: Issues an HTTP/2 request and returns the response.
|_    get_proxy_http_history: Displays items within the proxy HTTP history
```

## HexStrike AI

HexStrike AI commonly exposes a REST backend on port `8888`. The MCP server is
usually a stdio bridge (`hexstrike_mcp.py`) that talks to that backend, so port
`8888` is not normally a direct MCP HTTP endpoint.

The NSE script fingerprints this backend through `/health`:

```bash
nmap -Pn -p 8888 --script ./nse/mcp-info.nse --script-args mcp-info.paths=/health 127.0.0.1
```

If the backend exposes `tools_status`, the script lists those tool names. If it
only returns a minimal health response, it reports a low-confidence backend
fingerprint.

## Python CLI

The Python CLI mirrors the NSE logic and is mainly useful for development,
debugging, and regression tests.

Run from the repository:

```bash
python3 -m mcp_scanner 127.0.0.1 -p 9876 --paths /
```

JSON output:

```bash
python3 -m mcp_scanner 127.0.0.1 -p 9876 --paths / --json
```

Debug output:

```bash
python3 -m mcp_scanner 127.0.0.1 -p 8888 --paths /health --debug
```

Install the console script:

```bash
python3 -m pip install -e .
mcp-scan 127.0.0.1 -p 9876 --paths /
```

## Testing

The test suite starts local mock MCP services and also runs the NSE script with
Nmap when Nmap is installed.

```bash
python3 -m unittest -v
```

Validate that Nmap can load the script:

```bash
nmap --script-help ./nse/mcp-info.nse
```

### NSEDoc Link

`nmap --script-help` automatically prints an NSEDoc URL based on the script name,
for example:

```text
https://nmap.org/nsedoc/scripts/mcp-info.html
```

For local or third-party scripts this URL may not exist. It will only become a
real NSEDoc page if the script is accepted into Nmap's upstream script tree and
the public NSE documentation is regenerated.

## Upstreaming to Nmap

Nmap accepts contributions through GitHub pull requests and the development
mailing list.

Recommended process:

1. Fork the official Nmap repository: <https://github.com/nmap/nmap>
2. Add `mcp-info.nse` under `scripts/`.
3. Keep the script self-contained, safe by default, and compatible with Nmap's
   Lua/NSE libraries.
4. Use Nmap's license line in the script:

   ```lua
   license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
   ```

5. Run basic validation:

   ```bash
   nmap --script-help ./scripts/mcp-info.nse
   nmap -Pn -p <port> --script ./scripts/mcp-info.nse <target>
   ```

6. Open a pull request against <https://github.com/nmap/nmap>.
7. Send a short notification email to `dev@nmap.org` with the pull request link,
   the problem the script solves, supported MCP transports, and example output.

Useful official references:

- Nmap contribution guide: <https://github.com/nmap/nmap/blob/master/CONTRIBUTING.md>
- Nmap hacking guide: <https://github.com/nmap/nmap/blob/master/HACKING>
- Nmap development mailing list: <https://nmap.org/mailman/listinfo/dev>
- NSE script format: <https://nmap.org/book/nse-script-format.html>

## Safety Notes

- Scan only hosts and networks where you have authorization.
- The script does not call `tools/call`.
- The script does send discovery, initialization, and `tools/list` requests.
- Legacy SSE response endpoints are constrained to the scanned host/port.
- Treat discovered tool descriptions as potentially sensitive inventory data.

## Project Layout

```text
.
├── nse/
│   └── mcp-info.nse
├── mcp_scanner/
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py
│   └── scanner.py
├── tests/
│   ├── __init__.py
│   └── test_scanner.py
├── pyproject.toml
├── README.md
└── LICENSE
```

## License

The Python scanner, tests, and documentation are MIT licensed. The NSE script
declares Nmap-compatible licensing in the script header:

```lua
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
```
