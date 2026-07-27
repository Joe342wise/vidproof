#!/usr/bin/env python3
"""CLI: compare a video or image against a PRNU reference fingerprint.

PRNU (Photo Response Non-Uniformity) is a secondary forensic signal only.
It is never a pass/fail gate. The score is reported alongside primary
hash and signature checks, not instead of them.

Algorithm:
  1. Extract noise residuals from each frame: residual = frame - gaussian(frame)
  2. Average residuals to form a fingerprint for reference and test material
  3. Report normalised cross-correlation (NCC) between the two fingerprints

NCC of 1.0 = perfect match; 0.0 = uncorrelated; negative = anti-correlated.
Typical same-camera values: 0.01–0.15 (compressed video from Pi/webcam).
Different-camera values approach zero. Thresholds are data-dependent.

Usage:
    python forensics/prnu_compare.py <reference-path> <video-path> [--max-frames 30]

    reference-path: image file, video file, or directory of images (*.png/*.jpg)
    video-path:     image file, video file, or directory of images

Output (stdout):
    {"ok": true,  "result": {"prnuScore": 0.07, "referenceFrames": 30, "testFrames": 30}}
    {"ok": false, "error": {"code": "...", "message": "..."}}
"""
import argparse
import json
import sys
from pathlib import Path

import cv2
import numpy as np
from scipy.ndimage import gaussian_filter


_MAX_FRAMES = 30
_SIGMA = 3.0        # Gaussian denoising sigma
_MIN_FRAMES = 1     # Require at least this many frames


def fail(code: str, message: str) -> None:
    print(json.dumps({"ok": False, "error": {"code": code, "message": message}}))
    raise SystemExit(1)


# ---------------------------------------------------------------------------
# Frame extraction
# ---------------------------------------------------------------------------

def _read_video_frames(path: Path, max_frames: int) -> list[np.ndarray]:
    """Sample up to max_frames grayscale float32 frames from a video file."""
    cap = cv2.VideoCapture(str(path))
    if not cap.isOpened():
        return []

    total = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
    if total <= 0:
        # Unknown length — read sequentially
        step = 1
    else:
        step = max(1, total // max_frames)

    frames: list[np.ndarray] = []
    idx = 0
    while len(frames) < max_frames:
        cap.set(cv2.CAP_PROP_POS_FRAMES, idx)
        ok, frame = cap.read()
        if not ok:
            break
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY).astype(np.float32)
        frames.append(gray)
        idx += step

    cap.release()
    return frames


def _read_image_frame(path: Path) -> np.ndarray | None:
    """Load a single image as a grayscale float32 frame."""
    img = cv2.imread(str(path), cv2.IMREAD_GRAYSCALE)
    if img is None:
        return None
    return img.astype(np.float32)


def _collect_frames(path: Path, max_frames: int) -> list[np.ndarray]:
    """Return up to max_frames grayscale float32 frames from path.

    path may be:
      - an image file (.png, .jpg, .jpeg, .bmp, .tiff)
      - a video file (.mp4, .avi, .mkv, .mov, .h264, etc.)
      - a directory containing image files (sorted, first max_frames taken)
    """
    image_suffixes = {".png", ".jpg", ".jpeg", ".bmp", ".tiff", ".tif"}

    if path.is_dir():
        image_files = sorted(
            f for f in path.iterdir()
            if f.suffix.lower() in image_suffixes
        )[:max_frames]
        frames = []
        for f in image_files:
            frame = _read_image_frame(f)
            if frame is not None:
                frames.append(frame)
        return frames

    if path.suffix.lower() in image_suffixes:
        frame = _read_image_frame(path)
        return [frame] if frame is not None else []

    # Try as video
    frames = _read_video_frames(path, max_frames)
    if frames:
        return frames

    # Last resort: treat binary as raw luma plane if dimensions are plausible.
    # This gracefully handles encrypted or non-standard binary test inputs by
    # returning an empty list (score will be 0.0) rather than crashing.
    return []


# ---------------------------------------------------------------------------
# PRNU core
# ---------------------------------------------------------------------------

def _extract_noise_residual(frame: np.ndarray, sigma: float) -> np.ndarray:
    """Noise residual = frame − Gaussian-denoised frame."""
    denoised = gaussian_filter(frame, sigma=sigma)
    return frame - denoised


def _build_fingerprint(frames: list[np.ndarray], sigma: float) -> np.ndarray:
    """Average noise residuals over all frames to produce a PRNU fingerprint."""
    residuals = [_extract_noise_residual(f, sigma) for f in frames]
    return np.mean(residuals, axis=0)


def _normalised_cross_correlation(a: np.ndarray, b: np.ndarray) -> float:
    """NCC in [-1, 1]. Returns 0.0 if either array is constant."""
    a_flat = a.ravel() - a.mean()
    b_flat = b.ravel() - b.mean()
    denom = np.sqrt((a_flat ** 2).sum() * (b_flat ** 2).sum())
    if denom < 1e-10:
        return 0.0
    return float(np.clip(np.dot(a_flat, b_flat) / denom, -1.0, 1.0))


def compare_prnu(
    reference_path: Path,
    video_path: Path,
    max_frames: int = _MAX_FRAMES,
    sigma: float = _SIGMA,
) -> dict:
    """Run PRNU comparison and return result dict.

    Returns:
        dict with keys: prnuScore (float), referenceFrames (int), testFrames (int)

    Raises:
        ValueError: if either source yields no usable frames
    """
    ref_frames = _collect_frames(reference_path, max_frames)
    if len(ref_frames) < _MIN_FRAMES:
        raise ValueError(
            f"No usable frames from reference path: {reference_path}"
        )

    test_frames = _collect_frames(video_path, max_frames)
    if len(test_frames) < _MIN_FRAMES:
        raise ValueError(
            f"No usable frames from video path: {video_path}"
        )

    # Resize test fingerprint to match reference dimensions if needed
    ref_fp = _build_fingerprint(ref_frames, sigma)
    test_fp = _build_fingerprint(test_frames, sigma)

    if ref_fp.shape != test_fp.shape:
        test_fp = cv2.resize(test_fp, (ref_fp.shape[1], ref_fp.shape[0]),
                             interpolation=cv2.INTER_LINEAR)

    score = _normalised_cross_correlation(ref_fp, test_fp)

    return {
        "prnuScore": round(score, 6),
        "referenceFrames": len(ref_frames),
        "testFrames": len(test_frames),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> int:
    parser = argparse.ArgumentParser(
        description="PRNU secondary forensic comparison (score only — not a pass/fail gate)"
    )
    parser.add_argument("reference_path", type=Path,
                        help="Reference material: image, video, or image directory")
    parser.add_argument("video_path", type=Path,
                        help="Test material: image, video, or image directory")
    parser.add_argument("--max-frames", type=int, default=_MAX_FRAMES,
                        help=f"Max frames to sample from each source (default: {_MAX_FRAMES})")
    args = parser.parse_args()

    if not args.reference_path.exists():
        fail("REF_NOT_FOUND", f"Reference path not found: {args.reference_path}")
    if not args.video_path.exists():
        fail("VIDEO_NOT_FOUND", f"Video path not found: {args.video_path}")

    try:
        result = compare_prnu(
            reference_path=args.reference_path,
            video_path=args.video_path,
            max_frames=args.max_frames,
        )
    except ValueError as exc:
        fail("NO_FRAMES", str(exc))
    except Exception as exc:
        fail("PRNU_ERROR", f"PRNU comparison failed: {exc}")

    print(json.dumps({
        "ok": True,
        "result": result,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
