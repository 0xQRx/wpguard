#!/usr/bin/env python3
"""
PoC Template: Authenticated REST API Request
Usage: python3 poc.py --url http://172.17.0.1:8000
"""
import argparse
import re
import sys
import requests

# === CUSTOMIZE ===
REST_ROUTE = "/wp-json/namespace/v1/endpoint"  # Full REST route
HTTP_METHOD = "POST"                            # GET, POST, PUT, DELETE
USERNAME = "subscriber"
PASSWORD = "subscriber"
PAYLOAD = {
    # "param1": "value1",
}
EXPECTED_RESULT = {
    "status_code": 200,
    "body_contains": "success",
}
# === END CUSTOMIZE ===


def login(session, base_url):
    session.post(f"{base_url}/wp-login.php", data={
        "log": USERNAME, "pwd": PASSWORD,
        "wp-submit": "Log In",
        "redirect_to": f"{base_url}/wp-admin/",
        "testcookie": "1",
    }, allow_redirects=False)
    if "wordpress_logged_in" not in str(session.cookies):
        print(f"[FAIL] Login failed for {USERNAME}")
        sys.exit(1)
    print(f"[+] Logged in as {USERNAME}")


def get_rest_nonce(session, base_url):
    """Extract WP REST nonce from any admin page."""
    r = session.get(f"{base_url}/wp-admin/")
    match = re.search(r'"nonce":"([a-f0-9]+)"', r.text)
    if not match:
        match = re.search(r'wpApiSettings.*?"nonce"\s*:\s*"([a-f0-9]+)"', r.text)
    if not match:
        print("[FAIL] Could not find REST nonce")
        sys.exit(1)
    nonce = match.group(1)
    print(f"[+] Got REST nonce: {nonce}")
    return nonce


def exploit(session, base_url, nonce):
    headers = {"X-WP-Nonce": nonce}
    url = f"{base_url}{REST_ROUTE}"

    if HTTP_METHOD == "GET":
        r = session.get(url, headers=headers, params=PAYLOAD)
    elif HTTP_METHOD == "POST":
        r = session.post(url, headers=headers, json=PAYLOAD)
    elif HTTP_METHOD == "PUT":
        r = session.put(url, headers=headers, json=PAYLOAD)
    elif HTTP_METHOD == "DELETE":
        r = session.delete(url, headers=headers, json=PAYLOAD)
    else:
        r = session.post(url, headers=headers, json=PAYLOAD)
    return r


def verify(response):
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
    nonce = get_rest_nonce(session, args.url)
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
