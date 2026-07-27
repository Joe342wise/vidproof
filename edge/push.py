#!/usr/bin/env python3
"""Push locally captured evidence to the VidProof backend.

Reads the .enc file and evidence.json from local storage and posts them to
POST /evidence/ingest on the backend. On network failure the evidence ID is
written to a local outbox directory and retried on the next --flush-queue run.

Usage:
    # Push one evidence item immediately after capture
    python edge/push.py \\
        --evidence-id ev-abc123 \\
        --backend-url http://192.168.1.50:8000 \\
        [--storage-dir /var/vidproof/storage]

    # Flush all items that failed earlier
    python edge/push.py \\
        --flush-queue \\
        --backend-url http://192.168.1.50:8000 \\
        [--storage-dir /var/vidproof/storage]

Exit codes: 0 = success, 1 = one or more items failed or queued.
"""
import argparse
import json
import sys
import time
from pathlib import Path

import requests

_DEFAULT_BACKEND_URL = "http://vidproof-backend:8000"
_RETRY_DELAY_S = 30
_MAX_RETRIES = 3
_OUTBOX = "outbox"


# ---------------------------------------------------------------------------
# Core push logic
# ---------------------------------------------------------------------------

def push_one(
    evidence_id: str,
    storage_dir: Path,
    backend_url: str,
    timeout: int = 30,
) -> dict:
    """POST one evidence item to /evidence/ingest.

    Returns the backend response dict on HTTP success.
    Raises FileNotFoundError if local files are missing.
    Raises requests.exceptions.RequestException on network failure.
    """
    evidence_path = storage_dir / "metadata" / "evidence" / f"{evidence_id}.json"
    enc_path = storage_dir / "evidence" / f"{evidence_id}.enc"

    if not evidence_path.exists():
        raise FileNotFoundError(f"evidence.json not found: {evidence_path}")
    if not enc_path.exists():
        raise FileNotFoundError(f".enc file not found: {enc_path}")

    resp = requests.post(
        f"{backend_url.rstrip('/')}/evidence/ingest",
        data={"evidence_json": evidence_path.read_text()},
        files={"enc_file": (f"{evidence_id}.enc", enc_path.read_bytes(), "application/octet-stream")},
        timeout=timeout,
    )
    return resp.json()


# ---------------------------------------------------------------------------
# Outbox queue
# ---------------------------------------------------------------------------

def _outbox(storage_dir: Path) -> Path:
    p = storage_dir / _OUTBOX
    p.mkdir(parents=True, exist_ok=True)
    return p


def enqueue(evidence_id: str, storage_dir: Path) -> None:
    (_outbox(storage_dir) / f"{evidence_id}.pending").touch()


def dequeue(evidence_id: str, storage_dir: Path) -> None:
    (_outbox(storage_dir) / f"{evidence_id}.pending").unlink(missing_ok=True)


def list_pending(storage_dir: Path) -> list[str]:
    return [p.stem for p in sorted(_outbox(storage_dir).glob("*.pending"))]


# ---------------------------------------------------------------------------
# Retry wrapper
# ---------------------------------------------------------------------------

def _push_with_retry(
    evidence_id: str,
    storage_dir: Path,
    backend_url: str,
    *,
    queue_on_failure: bool,
) -> bool:
    """Push one item, retrying on transient network errors.

    Returns True on success, False on permanent failure.
    Queues the item in outbox/ if queue_on_failure and all retries exhausted.
    """
    for attempt in range(1, _MAX_RETRIES + 1):
        try:
            result = push_one(evidence_id, storage_dir, backend_url)
        except FileNotFoundError as exc:
            print(f"[{evidence_id}] local file missing — cannot push: {exc}", file=sys.stderr)
            return False
        except requests.exceptions.RequestException as exc:
            if attempt < _MAX_RETRIES:
                print(
                    f"[{evidence_id}] network error (attempt {attempt}/{_MAX_RETRIES}), "
                    f"retrying in {_RETRY_DELAY_S}s: {exc}",
                    file=sys.stderr,
                )
                time.sleep(_RETRY_DELAY_S)
                continue
            print(f"[{evidence_id}] gave up after {_MAX_RETRIES} attempts: {exc}", file=sys.stderr)
            if queue_on_failure:
                enqueue(evidence_id, storage_dir)
                print(f"[{evidence_id}] queued in outbox/ for later retry")
            return False

        if result.get("ok"):
            fabric_tx = result.get("fabricTxId") or "—"
            print(json.dumps({
                "ok": True,
                "evidenceId": evidence_id,
                "fabricTxId": fabric_tx,
            }))
            dequeue(evidence_id, storage_dir)
            return True
        else:
            # Server rejected the evidence (bad schema, duplicate ID, etc.)
            # — do not retry, this is not a transient error.
            err = result.get("detail", result.get("error", "backend rejected evidence"))
            print(f"[{evidence_id}] backend error: {err}", file=sys.stderr)
            return False

    return False  # unreachable but makes type checkers happy


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(description="Push VidProof evidence to the backend")
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--evidence-id", help="Push a single evidence item by ID")
    mode.add_argument("--flush-queue", action="store_true",
                      help="Push all items waiting in the outbox")
    parser.add_argument("--storage-dir", type=Path, default=Path("/var/vidproof/storage"),
                        help="Local VidProof storage root (default: /var/vidproof/storage)")
    parser.add_argument("--backend-url", default=_DEFAULT_BACKEND_URL,
                        help=f"Backend base URL (default: {_DEFAULT_BACKEND_URL})")
    parser.add_argument("--no-retry-queue", action="store_true",
                        help="Do not write to outbox on failure (fail immediately)")
    args = parser.parse_args()

    queue_on_failure = not args.no_retry_queue

    if args.flush_queue:
        pending = list_pending(args.storage_dir)
        if not pending:
            print("Outbox is empty — nothing to push.")
            return 0
        print(f"Flushing {len(pending)} queued item(s)…")
        failed = sum(
            0 if _push_with_retry(eid, args.storage_dir, args.backend_url,
                                   queue_on_failure=queue_on_failure) else 1
            for eid in pending
        )
        if failed:
            print(f"{len(pending) - failed} pushed, {failed} still pending.", file=sys.stderr)
            return 1
        print(f"All {len(pending)} item(s) pushed successfully.")
        return 0

    ok = _push_with_retry(
        args.evidence_id,
        args.storage_dir,
        args.backend_url,
        queue_on_failure=queue_on_failure,
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
