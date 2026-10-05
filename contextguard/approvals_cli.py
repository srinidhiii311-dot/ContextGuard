"""Admin-seeding CLI for ContextGuard approvals.

Usage:
    python -m contextguard.approvals_cli create-user NAME ROLE
Reads password from stdin.
"""
from __future__ import annotations

import argparse
import os
import sys

from contextguard.approvals import ApprovalService, connect


def main() -> None:
    parser = argparse.ArgumentParser(description="ContextGuard Approvals Management CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    create_user_parser = subparsers.add_parser("create-user", help="Create a user with a given role")
    create_user_parser.add_argument("name", help="Username")
    create_user_parser.add_argument("role", help="Role (viewer, analyst, approver, admin)")
    create_user_parser.add_argument("--db", default=None, help="Database path")

    args = parser.parse_args()

    if args.command == "create-user":
        db_path = args.db or os.getenv("DB_PATH", "contextguard.db")
        if sys.stdin.isatty():
            password = input("Enter password: ")
        else:
            password = sys.stdin.read().strip()

        if not password:
            print("Error: Password cannot be empty.", file=sys.stderr)
            sys.exit(1)

        conn = connect(db_path)
        svc = ApprovalService(conn)
        try:
            svc.create_user(args.name, password, role=args.role)
            print(f"[OK] User '{args.name}' with role '{args.role}' successfully created in '{db_path}'.")
        except Exception as e:
            print(f"Error creating user: {e}", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
