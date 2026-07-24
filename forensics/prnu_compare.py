#!/usr/bin/env python3
import json
import sys


def main() -> int:
    if len(sys.argv) != 3:
        print(json.dumps({"ok": False, "error": {"code": "USAGE", "message": "Usage: prnu_compare.py <reference-path> <video-path>"}}))
        return 2

    print(json.dumps({
        "ok": False,
        "error": {
            "code": "NOT_IMPLEMENTED",
            "message": "PRNU comparison is intentionally a secondary module and is not implemented yet"
        }
    }))
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
