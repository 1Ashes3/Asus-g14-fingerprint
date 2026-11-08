"""Configuration defaults and loading for asus_fp.

Values were tuned on an ASUS G14 GA401QM (Goodix 27c6:521d) and validated on saved captures
(genuine >= 0.77, impostor <= 0.70 with the dense-correlation matcher)."""
import json
import os

DEFAULTS = {
    # capture
    "mode": 0x01,                 # image command mode byte
    "dac": 0x107,                 # per-quadrant DAC base; calibrate.py picks this per unit
    "dac_offsets": [0, -6, 0, -4],
    "finger_threshold": -700,     # mean(frame - background) below this => finger present
    "bg_frames": 4,
    "calib_frames": 1000,
    "noise_mask_factor": 3.0,
    "noise_floor": 1.0,
    "min_ridge_ac": 0.15,         # frame quality gate (ridge-scale autocorrelation)
    # preprocessing / matching
    "preprocess": "clahe",        # "clahe" (default, user-preferred) or "dog"
    "min_overlap_px": 1600,
    "max_angle": 36, "angle_step": 3, "max_shift": 30,
    "pass_ncc": 0.78,
    "frames_required": 2,
    "single_frame_ncc": 0.84,
    "identity_veto_ncc": 0.90,
    # enrolment
    "enroll_cycles": 5,
    "enroll_frames_per_cycle": 8,
    "new_area_ncc": 0.85,
    "same_area_retries": 2,
    "max_templates": 100,
    "gain_map_min_frames": 12,
    # verification
    "verify_max_frames": 20,
    "verify_skip_frames": 1,
    "pam_timeout_s": 180,
}

SYSTEM_CONFIG = "/etc/asus-fp/config.json"
# app-side procedure settings always come from DEFAULTS (so upgrades take effect); the file only tunes matching/sensor
APP_ONLY = {"calib_frames", "enroll_cycles", "enroll_frames_per_cycle", "same_area_retries"}


def load(path=None):
    """Defaults overlaid with a JSON file (system config by default). Unknown and app-only keys are ignored."""
    cfg = dict(DEFAULTS)
    path = path or SYSTEM_CONFIG
    try:
        with open(path) as f:
            data = json.load(f)
        cfg.update({k: v for k, v in data.items() if k in DEFAULTS and k not in APP_ONLY})
    except (FileNotFoundError, PermissionError, ValueError):
        pass
    return cfg
