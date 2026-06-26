"""
ARK Rejoin Bot — License Key Admin Tool
=========================================
Run this locally to create, revoke, extend, and list license keys.
Never share this file or the ADMIN_TOKEN.

SETUP:
  pip install requests
  Set SERVER_URL and ADMIN_TOKEN below, or use environment variables.

USAGE:
  python license_keygen.py create  --email user@example.com --days 30
  python license_keygen.py revoke  --key XXXX.YYYY
  python license_keygen.py extend  --key XXXX.YYYY --days 30
  python license_keygen.py list
"""

import argparse
import os
import sys
import json
import requests

# ── Config — set these or use env vars ──
SERVER_URL  = os.environ.get("LICENSE_SERVER_URL", "https://your-app.railway.app")
ADMIN_TOKEN = os.environ.get("LICENSE_ADMIN_TOKEN", "change-this-admin-token")

HEADERS = {"X-Admin-Token": ADMIN_TOKEN, "Content-Type": "application/json"}


def create_key(email: str, days: int, notes: str = ""):
    resp = requests.post(
        f"{SERVER_URL}/admin/create",
        headers=HEADERS,
        json={"email": email, "days": days, "notes": notes},
        timeout=10
    )
    data = resp.json()
    if resp.status_code == 201:
        print("\n✔ License key created:")
        print(f"  Key:        {data['key']}")
        print(f"  Email:      {data['email']}")
        print(f"  Expires:    {data['expires_at']}")
        print(f"  Days:       {data['days']}")
        print(f"\n  → Send this key to the customer: {data['key']}\n")
    else:
        print(f"✗ Error: {data}")


def revoke_key(key: str):
    resp = requests.post(
        f"{SERVER_URL}/admin/revoke",
        headers=HEADERS,
        json={"key": key},
        timeout=10
    )
    data = resp.json()
    if resp.status_code == 200:
        print(f"✔ Key revoked: {key}")
    else:
        print(f"✗ Error: {data}")


def extend_key(key: str, days: int):
    resp = requests.post(
        f"{SERVER_URL}/admin/extend",
        headers=HEADERS,
        json={"key": key, "days": days},
        timeout=10
    )
    data = resp.json()
    if resp.status_code == 200:
        print(f"✔ Key extended: {key}")
        print(f"  New expiry: {data['new_expires_at']}")
    else:
        print(f"✗ Error: {data}")


def list_keys():
    resp = requests.get(
        f"{SERVER_URL}/admin/list",
        headers=HEADERS,
        timeout=10
    )
    keys = resp.json()
    if not keys:
        print("No license keys found.")
        return
    print(f"\n{'KEY':<22} {'EMAIL':<28} {'EXPIRES':<22} {'REVOKED':<8} {'LAST SEEN'}")
    print("─" * 100)
    for k in keys:
        revoked   = "YES" if k["revoked"] else "no"
        last_seen = k["last_seen"] or "never"
        print(f"{k['key']:<22} {k['email']:<28} {k['expires_at']:<22} {revoked:<8} {last_seen}")
    print(f"\nTotal: {len(keys)} keys\n")


def main():
    parser = argparse.ArgumentParser(description="ARK Rejoin Bot license admin")
    sub = parser.add_subparsers(dest="command")

    p_create = sub.add_parser("create", help="Create a new license key")
    p_create.add_argument("--email", required=True)
    p_create.add_argument("--days",  type=int, default=30)
    p_create.add_argument("--notes", default="")

    p_revoke = sub.add_parser("revoke", help="Revoke a license key")
    p_revoke.add_argument("--key", required=True)

    p_extend = sub.add_parser("extend", help="Extend a license key")
    p_extend.add_argument("--key",  required=True)
    p_extend.add_argument("--days", type=int, default=30)

    sub.add_parser("list", help="List all license keys")

    args = parser.parse_args()

    if args.command == "create":
        create_key(args.email, args.days, args.notes)
    elif args.command == "revoke":
        revoke_key(args.key)
    elif args.command == "extend":
        extend_key(args.key, args.days)
    elif args.command == "list":
        list_keys()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
