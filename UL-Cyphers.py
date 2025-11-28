#!/usr/bin/env python3

import glob
import os
import sys

from auth.hmac_authenticated_client import HMACAuthenticatedClient

DEFAULT_URL = "http://127.0.0.1:8080"
DEFAULT_DIR = os.path.join(os.path.dirname(__file__), "Cyphers")

# Import apikey, apiid, and url from BloodSOCer.py
try:
    from BloodSOCer import apikey, apiid, url
except Exception:
    apikey = None
    apiid = None
    url = DEFAULT_URL


def credentials_valid():
    invalid_values = {None, "", "<CHANGEME>"}
    return apikey not in invalid_values and apiid not in invalid_values


def import_file(httpx_client, path):
    with open(path, "rb") as fh:
        payload = fh.read()
    resp = httpx_client.post(
        "/api/v2/saved-queries/import",
        content=payload,
        headers={"Content-Type": "application/json"},
        timeout=60.0,
    )
    if resp.status_code < 400:
        print(f"[OK] imported {path} (status {resp.status_code})")
    else:
        print(f"[ERROR] import failed for {path} (status {resp.status_code}): {resp.text}")


def main():
    if not credentials_valid():
        print("[ERROR] apikey and apiid must be set in BloodSOCer.py before running this script.")
        sys.exit(1)

    # If files were passed on the command line, use them; otherwise default to all JSON under Cyphers/
    files = sys.argv[1:]
    if not files:
        files = glob.glob(os.path.join(DEFAULT_DIR, "**", "*.json"), recursive=True)
        files.sort()
        if not files:
            print(f"[ERROR] No JSON files found under {DEFAULT_DIR}")
            sys.exit(1)

    with HMACAuthenticatedClient(base_url=url, token_key=apikey, token_id=apiid) as client:
        httpx_client = client.get_httpx_client()
        for path in files:
            if not os.path.exists(path):
                print(f"[WARN] file not found: {path}")
                continue
            try:
                import_file(httpx_client, path)
            except Exception as exc:
                print(f"[ERROR] import failed for {path}: {exc}")


if __name__ == "__main__":
    main()
