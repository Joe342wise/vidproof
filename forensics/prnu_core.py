"""PRNU (Photo Response Non-Uniformity) fingerprint extraction and comparison.

Each camera sensor has a unique noise pattern baked into every frame.
Extract it by subtracting a denoised version of each frame, then average
across frames.  Compare query vs reference using normalised cross-correlation.

Scores:
  > 0.6  — strong match (same sensor, high confidence)
  0.3–0.6 — weak match (uncertain)
  < 0.3  — different sensor (or too few frames / noisy input)

PRNU is always a secondary signal — it never drives primaryDecision.
"""

import hashlib
import tempfile
from pathlib import Path

import numpy as np


def _noise_residual(gray: np.ndarray, sigma: float = 3.0) -> np.ndarray:
    """Subtract Gaussian-denoised version of a frame to isolate sensor noise."""
    from scipy.ndimage import gaussian_filter
    denoised = gaussian_filter(gray.astype(np.float32), sigma=sigma)
    return gray.astype(np.float32) - denoised


def extract_prnu(video_path: Path, max_frames: int = 50) -> tuple[np.ndarray, int]:
    """Extract averaged PRNU fingerprint from a video file path.

    Returns (fingerprint_array, frames_used).
    """
    import cv2
    cap = cv2.VideoCapture(str(video_path))
    if not cap.isOpened():
        raise ValueError(f"Cannot open video: {video_path}")
    residuals = []
    while len(residuals) < max_frames:
        ret, frame = cap.read()
        if not ret:
            break
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        residuals.append(_noise_residual(gray))
    cap.release()
    if not residuals:
        raise ValueError(f"No frames extracted from {video_path}")
    return np.mean(residuals, axis=0), len(residuals)


def extract_prnu_from_bytes(video_bytes: bytes, max_frames: int = 50) -> tuple[np.ndarray, int]:
    """Extract PRNU from raw video bytes by writing to a temp file.

    Returns (fingerprint_array, frames_used).
    """
    # Detect container format from magic bytes
    if len(video_bytes) >= 12 and video_bytes[4:8] in (b"ftyp", b"mdat", b"moov", b"free"):
        suffix = ".mp4"
    elif len(video_bytes) >= 4 and video_bytes[:3] == b"\x00\x00\x01":
        suffix = ".h264"
    elif len(video_bytes) >= 4 and video_bytes[:3] == b"\x1a\x45\xdf":
        suffix = ".mkv"
    else:
        suffix = ".mp4"

    with tempfile.NamedTemporaryFile(suffix=suffix, delete=False) as f:
        f.write(video_bytes)
        tmp = Path(f.name)
    try:
        return extract_prnu(tmp, max_frames=max_frames)
    finally:
        tmp.unlink(missing_ok=True)


def compare_prnu(reference: np.ndarray, query: np.ndarray) -> float:
    """Normalised cross-correlation between two PRNU patterns.

    Returns a score in [-1, 1].  Scores above ~0.5 indicate the same sensor.
    """
    import cv2
    if reference.shape != query.shape:
        query = cv2.resize(
            query.astype(np.float32),
            (reference.shape[1], reference.shape[0]),
        )
    ref = reference.flatten().astype(np.float64)
    qry = query.flatten().astype(np.float64)
    ref -= ref.mean()
    qry -= qry.mean()
    ref_n = np.linalg.norm(ref)
    qry_n = np.linalg.norm(qry)
    if ref_n == 0 or qry_n == 0:
        return 0.0
    return float(np.clip(np.dot(ref, qry) / (ref_n * qry_n), -1.0, 1.0))


def save_reference(prnu: np.ndarray, path: Path) -> str:
    """Save PRNU reference array to disk. Returns SHA-256 hash of the array."""
    path.parent.mkdir(parents=True, exist_ok=True)
    np.save(str(path), prnu)
    return hashlib.sha256(prnu.tobytes()).hexdigest()


def load_reference(path: Path) -> np.ndarray:
    """Load a saved PRNU reference array."""
    return np.load(str(path))
