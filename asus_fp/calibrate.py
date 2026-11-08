"""Per-unit calibration on blank (finger-free) frames: DAC operating point + long background + noise mask."""
import numpy as np

# Operating point (measured on a G14): with no finger the frame should be almost fully saturated
# (>= 94 % of pixels at 4095); a finger then lowers readings by ~1500-2000 counts into the middle of
# the range. Raising the DAC base by 1 lowers every pixel by ~70-75 counts. We look for the HIGHEST
# DAC at which the blank frame is still >= SAT_TARGET saturated (on this unit: 0x107).
SAT_TARGET = 0.94
DEAD_COL = 22


def _sat(frame):
    f = np.delete(frame, DEAD_COL, axis=1)
    return float((f >= 4095).mean()), float(f.mean())


def pick_dac(sensor, start=None, progress=None):
    """Returns (dac, blank_mean, saturation). Only reads frames; the DAC is a per-capture parameter."""
    dac = int(start if start is not None else sensor.c["dac"])
    seen = {}

    def measure(d):
        if d not in seen:
            sensor.set_dac(d)
            sat, mean = _sat(sensor.frame())
            seen[d] = (sat, mean)
            if progress:
                progress(f"DAC 0x{d:x}: blank mean {mean:.0f}, saturated {sat*100:.0f}%")
        return seen[d]

    # coarse: move in steps of 8 until we bracket the SAT_TARGET crossing
    sat, _ = measure(dac)
    step = 8 if sat >= SAT_TARGET else -8
    for _ in range(16):
        nxt = max(0x80, min(0x1ff, dac + step))
        s2, _ = measure(nxt)
        if (s2 >= SAT_TARGET) != (sat >= SAT_TARGET) or nxt in (0x80, 0x1ff):
            break
        dac, sat = nxt, s2
    hi_sat = [d for d, v in seen.items() if v[0] >= SAT_TARGET]
    base = max(hi_sat) if hi_sat else dac
    # fine: step up by 1 while still saturated
    while base < 0x1ff:
        s2, _ = measure(base + 1)
        if s2 < SAT_TARGET:
            break
        base += 1
    sensor.set_dac(base)
    sat, mean = seen[base]
    return base, mean, sat


def calibrate(sensor, progress=None):
    """Full calibration: DAC pick, then long background with noise mask.
    Returns dict(dac, bg, noise, mask_info, blank_mean, saturation)."""
    dac, mean, sat = pick_dac(sensor, progress=progress)
    n = sensor.c["calib_frames"]
    if progress:
        progress(f"capturing {n} blank frames at DAC 0x{dac:x} (~{n/16:.0f} s)")
    sensor.take_background(n, progress=lambda i, m: progress and progress(f"blank frames {i}/{m}") if i % 100 == 0 else None)
    return {"dac": dac, "bg": sensor.bg.copy(), "noise": None if sensor.noise is None else sensor.noise.copy(),
            "mask_info": sensor.mask_info, "blank_mean": mean, "saturation": sat}
