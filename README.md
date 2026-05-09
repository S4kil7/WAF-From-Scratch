# Custom WAF — Built from Scratch in Python

A hand-built Web Application Firewall written in **pure Python (stdlib only)**.  
It acts as a **reverse proxy**, inspects every HTTP request, and blocks attacks before they reach your vulnerable backend.

---

## Project context — Architecture

This project is one piece of a larger lab environment. Three different defenses are deployed side-by-side in front of the same vulnerable target application ([DVWA — Damn Vulnerable Web App](https://github.com/digininja/DVWA)), so their behaviour can be directly compared:

```
                        ┌─────────────────────────────────────────────┐
                        │              Your Machine                   │
                        │                                             │
  HTTP on port 8081 ───▶│  DVWA (unprotected)   — baseline, no WAF   │
                        │                                             │
  HTTP on port 8080 ───▶│  ModSecurity + OWASP CRS  — open-source    │
                        │           ↓ proxies to ↓                   │
                        │         DVWA (internal)                     │
                        │                                             │
  HTTP on port 8090 ───▶│  Custom WAF (this project) — hand-built    │
                        │           ↓ proxies to ↓                   │
                        │         DVWA (internal)                     │
                        └─────────────────────────────────────────────┘
```

| Port | Service | Role |
|------|---------|------|
| `8081` | DVWA — unprotected | Raw target; used to confirm vulnerabilities exist |
| `8080` | ModSecurity + OWASP CRS | Industry-standard open-source WAF (Phase 2) |
| `8090` | **Custom WAF** (this repo) | Hand-written WAF, no third-party dependencies (Phase 3) |

All three services are spun up together with a single `docker-compose up` command (see below). DVWA is never exposed to the internet — the whole lab runs locally.

---

## How the custom WAF works — the flow of a request

Understanding what the code actually does is the point of this project, so here is the full lifecycle of a request:

```
 Browser or attacker tool
         │
         │  HTTP request (GET /page?id=1' UNION SELECT…)
         ▼
 ┌───────────────────────────────────────────────┐
 │              waf.py — WAFHandler              │
 │                                               │
 │  1. Read the full request (method, path,      │
 │     headers, body)                            │
 │                                               │
 │  2. URL-decode every value                    │
 │     (%27 → ', %3C → <, etc.)                  │
 │     so encoded evasions don't slip through    │
 │                                               │
 │  3. Run all 16 regex rules against:           │
 │       • the URI / query string                │
 │       • selected headers (User-Agent, Cookie, │
 │         Referer, X-Forwarded-For)             │
 │       • the POST/PUT body                     │
 │                                               │
 │  4a. Rule matched → send 403 block page       │
 │      + write JSON entry to waf_blocked.log    │
 │                                               │
 │  4b. No match → forward request to DVWA       │
 │      and relay the response back              │
 │      + write line to waf_access.log           │
 └───────────────────────────────────────────────┘
         │                         │
    403 Forbidden             200 OK (or whatever
    (attacker sees            DVWA responds with)
     block page)
```

The WAF is a **reverse proxy**: the browser never talks directly to DVWA. All it knows is that it's talking to whatever is on port 8090.

---

## Project Structure

```
custom-waf/
├── waf.py              ← Main WAF (reverse proxy + inspection engine)
├── test_waf.py         ← Phase 4 attack test suite
├── Dockerfile          ← Container for the WAF
├── docker-compose.yml  ← Spins up the full 3-tier lab:
│                         DVWA + ModSecurity + Custom WAF.
├── README.md           ← This file
└── logs/               ← Created automatically at runtime.
    ├── waf_blocked.log     JSON log of every blocked request.
    ├── waf_access.log      Apache-style log of every allowed request.
    └── test_report_*.json  Output from test_waf.py runs.
```

---

## Quick Start

### Option A — Docker (recommended, full lab)

```bash
# Brings up DVWA + ModSecurity + Custom WAF
docker-compose up -d

# Watch custom WAF logs live
docker logs -f custom-waf
```

### Option B — Run locally (Python 3.8+, no pip required)

```bash
# 1. Start DVWA however you like (Docker, XAMPP, etc.) on port 8081
# 2. Run the WAF
python3 waf.py --backend http://localhost:8081 --port 8090

# With custom options
python3 waf.py \
    --host    0.0.0.0 \
    --port    8090 \
    --backend http://localhost:8081
```

Visit `http://localhost:8090` — all traffic now flows through the WAF.

---

## Detection Rules

| ID        | Category        | What it catches                          | Severity |
|-----------|-----------------|------------------------------------------|----------|
| SQLi-001  | SQL Injection   | `UNION SELECT` statements                | CRITICAL |
| SQLi-002  | SQL Injection   | Boolean bypass (`' OR 1=1`)              | HIGH     |
| SQLi-003  | SQL Injection   | Comment terminators (`--`, `#`, `/*`)   | MEDIUM   |
| SQLi-004  | SQL Injection   | DDL/DML (`DROP`, `INSERT`, `DELETE`)     | CRITICAL |
| SQLi-005  | SQL Injection   | Time-based blind (`SLEEP`, `BENCHMARK`) | HIGH     |
| SQLi-006  | SQL Injection   | Stacked queries (`;SELECT`)              | HIGH     |
| XSS-001   | XSS             | `<script>` tags                          | CRITICAL |
| XSS-002   | XSS             | `javascript:` URIs                       | HIGH     |
| XSS-003   | XSS             | Event handlers (`onerror=`, `onclick=`)  | HIGH     |
| XSS-004   | XSS             | `data:text/html` URIs                    | MEDIUM   |
| XSS-005   | XSS             | `vbscript:` URIs                         | HIGH     |
| PT-001    | Path Traversal  | `../` sequences                          | HIGH     |
| PT-002    | Path Traversal  | URL-encoded traversal (`%2e%2e%2f`)      | HIGH     |
| CMDi-001  | Command Inject  | Shell metacharacters (`|`, `;`, `` ` ``) | CRITICAL |
| CMDi-002  | Command Inject  | Dangerous binaries (`wget`, `curl`, …)   | HIGH     |
| SCAN-001  | Recon           | Scanner User-Agents (nikto, sqlmap, …)   | MEDIUM   |

### Inspection surfaces

- **URI** — full path + query string (URL-decoded before matching)
- **Headers** — `User-Agent`, `Referer`, `Cookie`, `X-Forwarded-For`
- **Body** — raw POST/PUT body (URL-decoded before matching)

---

## Logs

Two log files are written to `logs/`:

### `logs/waf_blocked.log` — JSON lines, one per blocked request

```json
{
  "timestamp":  "2025-07-10T14:23:01Z",
  "client_ip":  "172.18.0.1",
  "method":     "GET",
  "path":       "/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,2--",
  "rule_id":    "SQLi-001",
  "rule_name":  "SQL UNION SELECT",
  "severity":   "CRITICAL",
  "location":   "URI",
  "payload":    "/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,2--"
}
```

### `logs/waf_access.log` — Apache combined-style access log

```
172.18.0.1 - - [10/Jul/2025:14:23:05 +0000] "GET / HTTP/1.1" 200
```

---

## Running the Test Suite (Phase 4)

```bash
# Test the custom WAF
python3 test_waf.py --target http://localhost:8090

# Compare against the unprotected app
python3 test_waf.py --target http://localhost:8081

# Compare against ModSecurity
python3 test_waf.py --target http://localhost:8080

# Output full JSON results
python3 test_waf.py --target http://localhost:8090 --json
```

The test suite fires **SQLi, XSS, Path Traversal, CMDi, and Scanner** payloads plus
**legitimate requests** to measure false positives. A JSON report is saved to `logs/`.

---

## Extending the Rules

Rules live in the `RULES` list at the top of `waf.py`. Each rule is a dict:

```python
{
    "id":       "MY-001",
    "name":     "My custom rule",
    "pattern":  re.compile(r"malicious_pattern", re.IGNORECASE),
    "severity": "HIGH",           # CRITICAL / HIGH / MEDIUM / LOW
    # "targets": ["headers"],     # optional: restrict to specific surface
}
```

Restart the WAF after editing. No recompilation needed.

---

## Requirements

- Python 3.8+ (zero external dependencies — stdlib only)
- Docker + Docker Compose (optional, for the full lab)
