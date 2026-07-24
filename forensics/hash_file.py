#!/usr/bin/env python3
import hashlib
import json
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(json.dumps({"ok": False, "error": {"code": "USAGE", "message": "Usage: hash_file.py <path>"}}))
        return 2

    path = sys.argv[1]
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as file:
            for chunk in iter(lambda: file.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        print(json.dumps({"ok": False, "error": {"code": "READ_FAILED", "message": str(exc)}}))
        return 1

    print(json.dumps({"ok": True, "result": {"sha256": digest.hexdigest()}}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
