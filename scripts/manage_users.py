"""Create API users. Only a hash of each key is stored; the key is shown once.

    python scripts/manage_users.py add "Dr. Vidya Gaikwad" approver --file secrets/users.json
    python scripts/manage_users.py list --file secrets/users.json
    python scripts/manage_users.py remove "Name" --file secrets/users.json

Roles: viewer (read), analyst (also run the agents), approver (also make the human decisions).
Point TRC_USERS_FILE at this file. Keep it out of Git.
"""

from __future__ import annotations

import argparse
import json
import secrets
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from common.auth import ROLES, hash_key


def _read(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    return list(json.loads(path.read_text(encoding="utf-8")).get("users", []))


def _write(path: Path, users: list[dict[str, str]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"users": users}, indent=2) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["add", "list", "remove"])
    parser.add_argument("name", nargs="?")
    parser.add_argument("role", nargs="?", choices=ROLES)
    parser.add_argument("--file", default="secrets/users.json")
    args = parser.parse_args()
    path = Path(args.file)
    users = _read(path)

    if args.command == "list":
        for user in users:
            print(f"{user['name']}: {user['role']}")
        return 0
    if not args.name:
        parser.error("a name is required")
    if args.command == "remove":
        kept = [u for u in users if u["name"] != args.name]
        if len(kept) == len(users):
            print(f"No user named {args.name}.")
            return 1
        _write(path, kept)
        print(f"Removed {args.name}.")
        return 0
    if not args.role:
        parser.error(f"a role is required: {', '.join(ROLES)}")
    if any(u["name"] == args.name for u in users):
        print(f"{args.name} already exists. Remove them first to issue a new key.")
        return 1
    key = secrets.token_urlsafe(32)
    _write(path, [*users, {"name": args.name, "role": args.role, "key_sha256": hash_key(key)}])
    print(f"Created {args.name} ({args.role}). This key is shown only once:\n{key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
