#!/usr/bin/env python3
"""
Custom Web Application Firewall (WAF)
A reverse proxy with HTTP inspection, attack detection, logging, and blocking.
Author: Custom WAF Project - Phase 3
"""

import argparse
import json
import logging
import os
import re
import sys
import urllib.parse
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from io import BytesIO

import urllib.request
import urllib.error

# ─────────────────────────────────────────────
#  Configuration
# ─────────────────────────────────────────────
DEFAULT_LISTEN_HOST = "0.0.0.0"
DEFAULT_LISTEN_PORT = 8090
DEFAULT_BACKEND     = "http://localhost:8081"
LOG_FILE            = "logs/waf_blocked.log"
ACCESS_LOG_FILE     = "logs/waf_access.log"

# ─────────────────────────────────────────────
#  Logging Setup
# ─────────────────────────────────────────────
os.makedirs("logs", exist_ok=True)

# Blocked-requests log (JSON lines)
blocked_logger = logging.getLogger("waf.blocked")
blocked_logger.setLevel(logging.INFO)
blocked_fh = logging.FileHandler(LOG_FILE)
blocked_fh.setFormatter(logging.Formatter("%(message)s"))
blocked_logger.addHandler(blocked_fh)

# Access log (human-readable)
access_logger = logging.getLogger("waf.access")
access_logger.setLevel(logging.INFO)
access_fh = logging.FileHandler(ACCESS_LOG_FILE)
access_fh.setFormatter(logging.Formatter("%(message)s"))
access_logger.addHandler(access_fh)

# Console output
console = logging.getLogger("waf.console")
console.setLevel(logging.INFO)
ch = logging.StreamHandler(sys.stdout)
ch.setFormatter(logging.Formatter("\033[1;34m[WAF]\033[0m %(message)s"))
console.addHandler(ch)


# ─────────────────────────────────────────────
#  Attack Signatures
# ─────────────────────────────────────────────
RULES = [
    # ── SQL Injection ─────────────────────────
    {
        "id": "SQLi-001",
        "name": "SQL UNION SELECT",
        "pattern": re.compile(r"union\s+(?:all\s+)?select", re.IGNORECASE),
        "severity": "CRITICAL",
    },
    {
        "id": "SQLi-002",
        "name": "SQL OR 1=1 / Boolean bypass",
        "pattern": re.compile(r"'\s*(?:or|and)\s+[\w'\"]+\s*=\s*[\w'\"]+", re.IGNORECASE),
        "severity": "HIGH",
    },
    {
        "id": "SQLi-003",
        "name": "SQL comment injection",
        "pattern": re.compile(r"(?:--|#|/\*)", re.IGNORECASE),
        "severity": "MEDIUM",
    },
    {
        "id": "SQLi-004",
        "name": "SQL DROP / INSERT / UPDATE / DELETE",
        "pattern": re.compile(
            r"\b(?:drop|truncate|insert\s+into|update\s+\w+\s+set|delete\s+from)\b",
            re.IGNORECASE,
        ),
        "severity": "CRITICAL",
    },
    {
        "id": "SQLi-005",
        "name": "SQL SLEEP / BENCHMARK (time-based blind)",
        "pattern": re.compile(r"\b(?:sleep|benchmark|waitfor\s+delay)\s*\(", re.IGNORECASE),
        "severity": "HIGH",
    },
    {
        "id": "SQLi-006",
        "name": "SQL stacked queries (semicolon injection)",
        "pattern": re.compile(r";\s*(?:select|insert|update|delete|drop|exec)\b", re.IGNORECASE),
        "severity": "HIGH",
    },

    # ── Cross-Site Scripting ───────────────────
    {
        "id": "XSS-001",
        "name": "XSS <script> tag",
        "pattern": re.compile(r"<\s*script[\s>]", re.IGNORECASE),
        "severity": "CRITICAL",
    },
    {
        "id": "XSS-002",
        "name": "XSS javascript: URI",
        "pattern": re.compile(r"javascript\s*:", re.IGNORECASE),
        "severity": "HIGH",
    },
    {
        "id": "XSS-003",
        "name": "XSS event handler (onerror/onload/onclick…)",
        "pattern": re.compile(r"\bon\w+\s*=", re.IGNORECASE),
        "severity": "HIGH",
    },
    {
        "id": "XSS-004",
        "name": "XSS data: URI",
        "pattern": re.compile(r"data\s*:\s*(?:text/html|application/javascript)", re.IGNORECASE),
        "severity": "MEDIUM",
    },
    {
        "id": "XSS-005",
        "name": "XSS vbscript: URI",
        "pattern": re.compile(r"vbscript\s*:", re.IGNORECASE),
        "severity": "HIGH",
    },

    # ── Path Traversal ─────────────────────────
    {
        "id": "PT-001",
        "name": "Path Traversal (../)",
        "pattern": re.compile(r"(?:\.\./|\.\.\\){2,}", re.IGNORECASE),
        "severity": "HIGH",
    },
    {
        "id": "PT-002",
        "name": "Path Traversal (URL-encoded)",
        "pattern": re.compile(r"%2e%2e(?:%2f|%5c)", re.IGNORECASE),
        "severity": "HIGH",
    },

    # ── Command Injection ──────────────────────
    {
        "id": "CMDi-001",
        "name": "Command Injection (shell metacharacters)",
        "pattern": re.compile(r"(?<![&\w])[;|`$](?:\s*\w+)|&&\s*\w+", re.IGNORECASE),
        "severity": "CRITICAL",
    },
    {
        "id": "CMDi-002",
        "name": "Command Injection (common commands)",
        "pattern": re.compile(
            r"\b(?:cat|ls|wget|curl|bash|sh|python|perl|nc|netcat)\s+", re.IGNORECASE
        ),
        "severity": "HIGH",
    },

    # ── Scanner / Recon ────────────────────────
    {
        "id": "SCAN-001",
        "name": "Vulnerability Scanner User-Agent",
        "pattern": re.compile(
            r"(?:nikto|sqlmap|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|hydra|burpsuite)",
            re.IGNORECASE,
        ),
        "severity": "MEDIUM",
        "targets": ["headers"],   # only check headers for this rule
    },
]


# ─────────────────────────────────────────────
#  403 Block Page (custom HTML)
# ─────────────────────────────────────────────
BLOCK_PAGE = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>403 — Request Blocked</title>
  <style>
    @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@600;700&display=swap');

    *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

    :root {{
      --red:    #ff2d2d;
      --amber:  #ffb700;
      --dark:   #0a0a0f;
      --panel:  #0f1117;
      --border: #1e2130;
      --text:   #c8cfe8;
      --mono:   'Share Tech Mono', monospace;
      --head:   'Rajdhani', sans-serif;
    }}

    body {{
      background: var(--dark);
      color: var(--text);
      font-family: var(--mono);
      min-height: 100vh;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 2rem;
      overflow: hidden;
    }}

    /* animated scanline */
    body::before {{
      content: '';
      position: fixed; inset: 0;
      background: repeating-linear-gradient(
        to bottom,
        transparent 0px,
        transparent 3px,
        rgba(0,0,0,.18) 3px,
        rgba(0,0,0,.18) 4px
      );
      pointer-events: none;
      z-index: 10;
    }}

    .card {{
      background: var(--panel);
      border: 1px solid var(--border);
      border-top: 3px solid var(--red);
      max-width: 640px;
      width: 100%;
      padding: 2.5rem 3rem;
      position: relative;
      box-shadow: 0 0 60px rgba(255,45,45,.12), 0 0 120px rgba(255,45,45,.05);
    }}

    .badge {{
      display: inline-flex;
      align-items: center;
      gap: .5rem;
      font-family: var(--head);
      font-size: .7rem;
      letter-spacing: .2em;
      text-transform: uppercase;
      color: var(--red);
      border: 1px solid rgba(255,45,45,.35);
      padding: .3rem .75rem;
      margin-bottom: 1.5rem;
    }}

    .badge::before {{
      content: '';
      display: inline-block;
      width: 7px; height: 7px;
      background: var(--red);
      border-radius: 50%;
      animation: blink 1s step-end infinite;
    }}

    @keyframes blink {{ 50% {{ opacity: 0; }} }}

    h1 {{
      font-family: var(--head);
      font-size: clamp(2.5rem, 6vw, 4rem);
      font-weight: 700;
      color: #fff;
      line-height: 1;
      margin-bottom: .5rem;
    }}

    h1 span {{ color: var(--red); }}

    .subtitle {{
      font-size: .85rem;
      color: #5a6082;
      margin-bottom: 2rem;
    }}

    .divider {{
      border: none;
      border-top: 1px solid var(--border);
      margin: 1.5rem 0;
    }}

    .detail-grid {{
      display: grid;
      grid-template-columns: auto 1fr;
      gap: .5rem 1.5rem;
      font-size: .8rem;
    }}

    .key  {{ color: #5a6082; }}
    .val  {{ color: var(--amber); word-break: break-all; }}
    .val.rule {{ color: var(--red); }}

    .footer {{
      margin-top: 2rem;
      font-size: .72rem;
      color: #2e3350;
      display: flex;
      justify-content: space-between;
    }}

    .corner {{
      position: absolute;
      width: 12px; height: 12px;
      border-color: var(--red);
      border-style: solid;
    }}
    .corner.tl {{ top: -1px; left: -1px;  border-width: 2px 0 0 2px; }}
    .corner.tr {{ top: -1px; right: -1px; border-width: 2px 2px 0 0; }}
    .corner.bl {{ bottom: -1px; left: -1px;  border-width: 0 0 2px 2px; }}
    .corner.br {{ bottom: -1px; right: -1px; border-width: 0 2px 2px 0; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="corner tl"></div><div class="corner tr"></div>
    <div class="corner bl"></div><div class="corner br"></div>

    <div class="badge">Threat Neutralised</div>
    <h1><span>403</span> Forbidden</h1>
    <p class="subtitle">Your request was intercepted and blocked by the Custom WAF.</p>

    <hr class="divider" />

    <div class="detail-grid">
      <span class="key">Timestamp</span>   <span class="val">{timestamp}</span>
      <span class="key">Your IP</span>     <span class="val">{client_ip}</span>
      <span class="key">Rule ID</span>     <span class="val rule">{rule_id}</span>
      <span class="key">Rule Name</span>   <span class="val rule">{rule_name}</span>
      <span class="key">Severity</span>    <span class="val">{severity}</span>
      <span class="key">Request</span>     <span class="val">{method} {path}</span>
    </div>

    <div class="footer">
      <span>Custom WAF — Phase 3</span>
      <span>ref: {ref_id}</span>
    </div>
  </div>
</body>
</html>
"""


# ─────────────────────────────────────────────
#  Inspection Engine
# ─────────────────────────────────────────────
def inspect(value: str, targets_filter=None) -> dict | None:
    """
    Run all rules against *value*.
    Returns the first matching rule dict, or None if clean.
    targets_filter: if set, only run rules whose 'targets' list contains this string.
    """
    for rule in RULES:
        rule_targets = rule.get("targets")
        if targets_filter and rule_targets and targets_filter not in rule_targets:
            continue
        if rule_targets and not targets_filter:
            continue   # header-only rules skip body/URI checks
        if rule["pattern"].search(value):
            return rule
    return None


def decode_value(value: str) -> str:
    """URL-decode and HTML-entity decode a value for deeper inspection."""
    try:
        decoded = urllib.parse.unquote_plus(value)
    except Exception:
        decoded = value
    return decoded


def check_request(method, path, headers, body_bytes) -> dict | None:
    """
    Inspect every surface of the request.
    Returns a dict with { rule, location, payload } if malicious, else None.
    """
    # 1. URI (path + query string)
    decoded_path = decode_value(path)
    hit = inspect(decoded_path)
    if hit:
        return {"rule": hit, "location": "URI", "payload": path[:200]}

    # 2. Headers (User-Agent, Referer, Cookie, custom headers)
    suspicious_headers = ["user-agent", "referer", "cookie", "x-forwarded-for", "x-real-ip"]
    for hdr in suspicious_headers:
        val = headers.get(hdr, "")
        if val:
            decoded_val = decode_value(val)
            hit = inspect(decoded_val, targets_filter="headers") or inspect(decoded_val)
            if hit:
                return {"rule": hit, "location": f"Header:{hdr}", "payload": val[:200]}

    # 3. Body (POST data)
    if body_bytes:
        try:
            body_str = body_bytes.decode("utf-8", errors="replace")
        except Exception:
            body_str = ""
        decoded_body = decode_value(body_str)
        hit = inspect(decoded_body)
        if hit:
            return {"rule": hit, "location": "Body", "payload": body_str[:200]}

    return None


# ─────────────────────────────────────────────
#  Logging helpers
# ─────────────────────────────────────────────
def log_blocked(client_ip, method, path, detection):
    entry = {
        "timestamp":   datetime.now(timezone.utc).isoformat() + "Z",
        "client_ip":   client_ip,
        "method":      method,
        "path":        path,
        "rule_id":     detection["rule"]["id"],
        "rule_name":   detection["rule"]["name"],
        "severity":    detection["rule"]["severity"],
        "location":    detection["location"],
        "payload":     detection["payload"],
    }
    blocked_logger.info(json.dumps(entry))
    console.info(
        f"\033[1;31m[BLOCKED]\033[0m {client_ip} {method} {path} "
        f"— Rule {entry['rule_id']} ({entry['rule_name']})"
    )


def log_access(client_ip, method, path, status):
    ts = datetime.now(timezone.utc).strftime("%d/%b/%Y:%H:%M:%S +0000")
    access_logger.info(f'{client_ip} - - [{ts}] "{method} {path}" {status}')


# ─────────────────────────────────────────────
#  Proxy Handler
# ─────────────────────────────────────────────
class WAFHandler(BaseHTTPRequestHandler):

    backend: str = DEFAULT_BACKEND   # set at startup

    # silence default request log (we do our own)
    def log_message(self, fmt, *args):
        pass

    def _client_ip(self):
        xff = self.headers.get("X-Forwarded-For", "")
        if xff:
            return xff.split(",")[0].strip()
        return self.client_address[0]

    def _read_body(self) -> bytes:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            return self.rfile.read(content_length)
        return b""

    def _send_403(self, detection):
        import uuid
        ts   = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        page = BLOCK_PAGE.format(
            timestamp = ts,
            client_ip = self._client_ip(),
            rule_id   = detection["rule"]["id"],
            rule_name = detection["rule"]["name"],
            severity  = detection["rule"]["severity"],
            method    = self.command,
            path      = self.path[:60],
            ref_id    = str(uuid.uuid4())[:8].upper(),
        )
        body = page.encode("utf-8")
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-WAF-Block", detection["rule"]["id"])
        self.end_headers()
        self.wfile.write(body)

    def _proxy(self, body_bytes):
        """Forward the request to the backend and relay the response."""
        target_url = self.backend.rstrip("/") + self.path

        req = urllib.request.Request(target_url, data=body_bytes or None, method=self.command)

        # copy original headers (skip hop-by-hop)
        skip = {"connection", "keep-alive", "proxy-connection",
                "transfer-encoding", "upgrade", "host"}
        for key, val in self.headers.items():
            if key.lower() not in skip:
                req.add_header(key, val)
        req.add_header("Host", urllib.parse.urlparse(self.backend).netloc)
        req.add_header("X-Forwarded-For", self._client_ip())

        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                status  = resp.status
                headers = resp.headers
                content = resp.read()
        except urllib.error.HTTPError as e:
            status  = e.code
            headers = e.headers
            content = e.read()
        except Exception as e:
            self.send_error(502, f"Bad Gateway: {e}")
            return

        self.send_response(status)
        hop_by_hop = {"connection","keep-alive","transfer-encoding","te",
                      "trailers","upgrade","proxy-authorization","proxy-authenticate"}
        for key, val in headers.items():
            if key.lower() not in hop_by_hop and key.lower() != "content-length":
                self.send_header(key, val)
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)
        log_access(self._client_ip(), self.command, self.path, status)

    def handle_any(self):
        client_ip = self._client_ip()
        body = self._read_body()

        # ── INSPECTION ──
        detection = check_request(
            method=self.command,
            path=self.path,
            headers=self.headers,
            body_bytes=body,
        )

        if detection:
            log_blocked(client_ip, self.command, self.path, detection)
            self._send_403(detection)
        else:
            self._proxy(body)

    # map HTTP verbs to the same handler
    do_GET     = handle_any
    do_POST    = handle_any
    do_PUT     = handle_any
    do_DELETE  = handle_any
    do_PATCH   = handle_any
    do_HEAD    = handle_any
    do_OPTIONS = handle_any


# ─────────────────────────────────────────────
#  Entry Point
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Custom WAF Reverse Proxy")
    parser.add_argument("--host",    default=DEFAULT_LISTEN_HOST, help="Bind address")
    parser.add_argument("--port",    type=int, default=DEFAULT_LISTEN_PORT, help="Listen port")
    parser.add_argument("--backend", default=DEFAULT_BACKEND, help="Backend URL (e.g. http://localhost:8081)")
    args = parser.parse_args()

    WAFHandler.backend = args.backend

    console.info(f"Starting Custom WAF on {args.host}:{args.port}")
    console.info(f"Backend: {args.backend}")
    console.info(f"Rules loaded: {len(RULES)}")
    console.info(f"Blocked log:  {LOG_FILE}")
    console.info(f"Access log:   {ACCESS_LOG_FILE}")
    console.info("─" * 50)

    server = HTTPServer((args.host, args.port), WAFHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.info("WAF stopped.")


if __name__ == "__main__":
    main()
