#!/usr/bin/env python3
"""
PoC Template: Unauthenticated REST API Request
Usage: python3 poc.py --url http://172.17.0.1:8000
"""
import argparse
import sys
import requests

# === CUSTOMIZE ===
REST_ROUTE = "/wp-json/namespace/v1/endpoint"
HTTP_METHOD = "POST"
PAYLOAD = {
    # "param1": "value1",
}
EXPECTED_RESULT = {
    "status_code": 200,
    "body_contains": "success",
}
# === END CUSTOMIZE ===


def exploit(base_url):
    url = f"{base_url}{REST_ROUTE}"
    if HTTP_METHOD == "GET":
        r = requests.get(url, params=PAYLOAD)
    elif HTTP_METHOD == "POST":
        r = requests.post(url, json=PAYLOAD)
    elif HTTP_METHOD == "PUT":
        r = requests.put(url, json=PAYLOAD)
    elif HTTP_METHOD == "DELETE":
        r = requests.delete(url, json=PAYLOAD)
    else:
        r = requests.post(url, json=PAYLOAD)
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

    print(f"[*] Target: {args.url}{REST_ROUTE}")
    print(f"[*] Method: {HTTP_METHOD} (unauthenticated)")
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
