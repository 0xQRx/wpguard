#!/usr/bin/env python3
"""
PoC Template: Authenticated AJAX Request
Usage: python3 poc.py --url http://172.17.0.1:8000
"""
import argparse
import re
import sys
import requests

# === CUSTOMIZE ===
AJAX_ACTION = "your_ajax_action"          # The wp_ajax_ action name
NONCE_ACTION = "your_nonce_action"        # Nonce action name
NONCE_PAGE = "/wp-admin/admin.php?page=your-plugin"  # Page where nonce is rendered
NONCE_REGEX = r'["\']_wpnonce["\']\s*[,:]\s*["\']([a-f0-9]+)["\']'
USERNAME = "subscriber"
PASSWORD = "subscriber"
PAYLOAD = {
    # "param1": "value1",
    # "param2": "value2",
}
EXPECTED_RESULT = {
    "status_code": 200,
    "body_contains": "success",
}
# === END CUSTOMIZE ===


def login(session, base_url):
    """Login and return authenticated session."""
    r = session.post(f"{base_url}/wp-login.php", data={
        "log": USERNAME,
        "pwd": PASSWORD,
        "wp-submit": "Log In",
        "redirect_to": f"{base_url}/wp-admin/",
        "testcookie": "1",
    }, allow_redirects=False)
    if "wordpress_logged_in" not in str(session.cookies):
        print(f"[FAIL] Login failed for {USERNAME}")
        sys.exit(1)
    print(f"[+] Logged in as {USERNAME}")


def get_nonce(session, base_url):
    """Extract nonce from plugin page."""
    r = session.get(f"{base_url}{NONCE_PAGE}")
    match = re.search(NONCE_REGEX, r.text)
    if not match:
        print(f"[FAIL] Could not find nonce on {NONCE_PAGE}")
        sys.exit(1)
    nonce = match.group(1)
    print(f"[+] Got nonce: {nonce}")
    return nonce


def exploit(session, base_url, nonce):
    """Send the exploit AJAX request."""
    data = {
        "action": AJAX_ACTION,
        "_wpnonce": nonce,
        **PAYLOAD,
    }
    r = session.post(f"{base_url}/wp-admin/admin-ajax.php", data=data)
    return r


def verify(response):
    """Check if exploit succeeded."""
    ok = True
    if EXPECTED_RESULT.get("status_code") and response.status_code != EXPECTED_RESULT["status_code"]:
        ok = False
    if EXPECTED_RESULT.get("body_contains") and EXPECTED_RESULT["body_contains"] not in response.text:
        ok = False
    return ok


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://172.17.0.1:8000")
    args = parser.parse_args()

    session = requests.Session()
    login(session, args.url)
    nonce = get_nonce(session, args.url)
    response = exploit(session, args.url, nonce)

    print(f"[*] Response: {response.status_code}")
    print(f"[*] Body: {response.text[:500]}")

    if verify(response):
        print("\n[SUCCESS] Exploit confirmed!")
        sys.exit(0)
    else:
        print("\n[FAIL] Exploit did not produce expected result")
        sys.exit(1)


if __name__ == "__main__":
    main()
