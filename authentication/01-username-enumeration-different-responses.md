# Username Enumeration via Different Responses

**Lab:** PortSwigger Web Security Academy — Authentication
**Difficulty:** Apprentice
**Category:** Authentication / Username Enumeration & Brute-Force

## Problem

The application's login form is vulnerable to username enumeration. When an invalid
username is submitted, the server returns a distinct error message ("Invalid username")
compared to when a valid username is submitted with a wrong password ("Incorrect
password"). This difference in response content lets an attacker confirm which
usernames exist in the system before attempting to brute-force passwords — turning a
single combined brute-force problem into two much smaller, sequential ones.

## Discovery / Exploitation

1. With Burp running, submitted an invalid username/password pair on the login form and
   captured the `POST /login` request in Proxy > HTTP history.
2. Sent the request to Intruder and marked the `username` parameter as the payload
   position:
   ```
   username=§invalid-username§&password=static-value
   ```
3. Attack type: **Sniper**. Payload type: **Simple list**, loaded with the candidate
   usernames wordlist.
4. Ran the attack and sorted results by the **Length** column. One response stood out
   as longer than the rest.
5. Inspected that response body — every other payload returned `Invalid username`, but
   this one returned `Incorrect password`. This confirmed a valid username.

Noted the identified username, then pivoted to brute-forcing its password:

6. Cleared the username payload position, hardcoded the confirmed username, and marked
   `password` as the new payload position instead:
   ```
   username=identified-user&password=§invalid-password§
   ```
7. Loaded the candidate passwords wordlist as a Simple list payload and launched the
   attack.
8. Sorted results by **Status code**. Every request returned `200` (failed login)
   except one, which returned `302` — a redirect indicating a successful login.

## Proof of Concept

- Enumerated username via differential error messages (`Invalid username` vs
  `Incorrect password`) using Burp Intruder Sniper attack against the candidate
  usernames list.
- Brute-forced the corresponding password using the same technique, keying off the
  `302` redirect status code as the success signal instead of response content.
- Logged in with the recovered credentials and reached the user account page,
  confirming the vulnerability.

## Remediation

- Return an identical, generic error message (e.g. "Invalid username or password")
  regardless of whether the username or the password was wrong.
- Ensure the response time, length, and status code are also consistent across both
  failure cases — timing and length side-channels can leak the same information even
  if the message text is unified.
- Implement account lockout or rate-limiting/CAPTCHA after a threshold of failed login
  attempts to blunt automated brute-forcing even if enumeration is fixed.
