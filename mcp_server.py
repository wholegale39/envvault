"""MCP protocol server for EnvVault — lets Agents request credentials via MCP.

Implements the Model Context Protocol (JSON-RPC 2.0) over stdio or HTTP.
Exposes:
- tools/list: list available credential names
- tools/call get_credential: retrieve a credential value (audited)
- tools/call list_vault: list all credentials (names only, no values)
"""

from __future__ import annotations

import json
import os
import sys
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

import httpx
from loguru import logger


MCP_TOOLS = [
    {
        "name": "get_credential",
        "description": "Retrieve a credential value from the vault by name. "
                       "Every access is logged with agent identity and timestamp.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Credential name (e.g. LLM_API_KEY, GITHUB_TOKEN)"
                },
                "agent": {
                    "type": "string",
                    "description": "Optional agent/task identifier for audit logging"
                }
            },
            "required": ["name"]
        }
    },
    {
        "name": "list_credentials",
        "description": "List all credential names available in the vault (no values returned).",
        "inputSchema": {
            "type": "object",
            "properties": {}
        }
    },
]


class MCPVaultServer:
    """MCP server that proxies to the EnvVault HTTP API."""

    def __init__(self, vault_base_url: str = "http://localhost:8766"):
        self.vault_url = vault_base_url.rstrip("/")
        self._client: Optional[httpx.Client] = None

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(base_url=self.vault_url, timeout=10.0)
        return self._client

    def handle_request(self, request: dict) -> dict:
        """Handle a single JSON-RPC request."""
        req_id = request.get("id")
        method = request.get("method", "")
        params = request.get("params", {})

        if method == "tools/list":
            return self._make_response(req_id, {"tools": MCP_TOOLS})

        elif method == "tools/call":
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})

            if tool_name == "get_credential":
                return self._handle_get_credential(req_id, tool_args)
            elif tool_name == "list_credentials":
                return self._handle_list_credentials(req_id)
            else:
                return self._make_error(req_id, -32601, f"Unknown tool: {tool_name}")

        elif method == "initialize":
            return self._make_response(req_id, {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {
                    "name": "envvault-mcp",
                    "version": "0.2.0"
                }
            })

        elif method == "notifications/initialized":
            return None  # No response needed

        else:
            return self._make_error(req_id, -32601, f"Method not found: {method}")

    def _handle_get_credential(self, req_id: Any, args: dict) -> dict:
        name = args.get("name", "")
        agent = args.get("agent", "unknown")

        if not name:
            return self._make_error(req_id, -32602, "Missing required parameter: name")

        client = self._get_client()

        try:
            # List all secrets to find by name
            resp = client.get("/api/secrets")
            resp.raise_for_status()
            secrets = resp.json()

            # Find secret by name (case-insensitive)
            secret = None
            for s in secrets:
                if s["name"].strip().upper() == name.strip().upper():
                    secret = s
                    break

            if not secret:
                return self._make_error(req_id, -32000, f"Credential '{name}' not found in vault")

            # Reveal the value
            reveal = client.get(f"/api/secrets/{secret['id']}/reveal")
            reveal.raise_for_status()
            data = reveal.json()

            # Log audit via vault API directly (add to audit table)
            self._log_audit(name, agent, "granted")

            return self._make_response(req_id, {
                "name": data["name"],
                "value": data["value"],
            })

        except httpx.HTTPStatusError as e:
            return self._make_error(req_id, -32000, f"Vault API error: {e.response.status_code}")
        except Exception as e:
            return self._make_error(req_id, -32000, f"Vault connection failed: {e}")

    def _handle_list_credentials(self, req_id: Any) -> dict:
        client = self._get_client()
        try:
            resp = client.get("/api/secrets")
            resp.raise_for_status()
            secrets = resp.json()
            names_only = [{"name": s["name"], "group": s.get("group_name", ""),
                          "created_at": s.get("created_at", "")} for s in secrets]
            return self._make_response(req_id, {"credentials": names_only})
        except Exception as e:
            return self._make_error(req_id, -32000, f"Vault connection failed: {e}")

    def _log_audit(self, credential_name: str, agent: str, action: str):
        """Log an audit entry by calling the vault's audit API."""
        try:
            client = self._get_client()
            client.post("/api/audit", json={
                "credential_name": credential_name,
                "agent": agent,
                "action": action,
            })
        except Exception:
            pass  # Audit failure shouldn't block credential access

    def _make_response(self, req_id: Any, result: dict) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "result": result}

    def _make_error(self, req_id: Any, code: int, message: str) -> dict:
        return {"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}}


# ── Stdio mode (for Hermes MCP stdio transport) ───────────

def run_stdio():
    """Run as stdio MCP server — reads JSON-RPC from stdin, writes to stdout."""
    server = MCPVaultServer()
    logger.remove()
    logger.add(sys.stderr, level="WARNING")

    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            request = json.loads(line)
            response = server.handle_request(request)
            if response is not None:
                sys.stdout.write(json.dumps(response) + "\n")
                sys.stdout.flush()
        except json.JSONDecodeError:
            error = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "Parse error"}}
            sys.stdout.write(json.dumps(error) + "\n")
            sys.stdout.flush()


# ── HTTP mode (for network-accessible MCP endpoint) ───────

def run_http(host: str = "0.0.0.0", port: int = 8769):
    """Run as HTTP MCP server using built-in http.server (no FastAPI dep)."""
    import json
    from http.server import HTTPServer, BaseHTTPRequestHandler

    server = MCPVaultServer()

    class MCPHandler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/mcp":
                self.send_response(404)
                self.end_headers()
                return
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length))
            response = server.handle_request(body)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            if response is not None:
                self.wfile.write(json.dumps(response).encode())

        def do_GET(self):
            if self.path == "/health":
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"status": "ok", "server": "envvault-mcp"}).encode())
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, fmt, *args):
            pass  # Quiet

    httpd = HTTPServer((host, port), MCPHandler)
    print(f"MCP HTTP server on http://{host}:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "stdio"
    if mode == "http":
        port = int(sys.argv[2]) if len(sys.argv) > 2 else 8769
        run_http(port=port)
    else:
        run_stdio()
