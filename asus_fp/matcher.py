"""Preprocessing, per-unit gain map and the dense masked-NCC matcher (validated on saved
captures: genuine >= 0.77 cross-session, impostor <= 0.70)."""
import cv2
import numpy as np

from .sensor import AH, W, DEAD_COL, detrend

PH, PW = 128, 128                        # FFT size (>= 2*AH-1, 2*W-1)
_ONES = np.ones((AH, W), np.float32)
DOG_SIGMAS = (2.0, 6.0)


# ---------------- preprocessing ----------------
def build_gain_map(diffs, min_frames=12):
    """Per-pixel multiplicative gain pattern of this sensor unit: median of >= min_frames
    finger-minus-background frames, normalised to mean 1, clipped to [0.5, 2]. None if too few."""
    diffs = [d for d in diffs if d is not None]
    if len(diffs) < min_frames:
        return None
    g = np.median(np.stack(diffs), axis=0)
    g = g / (g.mean() if abs(g.mean()) > 1e-6 else 1.0)
    return sanitize_gain(g)


def sanitize_gain(g):
    """Gain maps must be finite and within [0.5, 2] (zeros/NaNs would poison every frame)."""
    if g is None or np.size(g) == 0:
        return None
    g = np.asarray(g, np.float32).copy()
    g[~np.isfinite(g)] = 1.0
    return np.clip(g, 0.5, 2.0)


def preprocess_diff(diff, gain=None, variant="clahe"):
    """finger - background (float32 60x64) -> uint8 image for matching."""
    d = diff / gain if gain is not None else diff
    d = detrend(d)
    d[:, DEAD_COL] = (d[:, DEAD_COL - 1] + d[:, DEAD_COL + 1]) / 2
    lo, hi = np.percentile(d, 1), np.percentile(d, 99)
    u8 = np.clip((d - lo) * 255 / max(hi - lo, 1), 0, 255).astype(np.uint8)
    u8 = cv2.GaussianBlur(u8, (3, 3), 0.8)
    if variant == "dog":
        x = u8.astype(np.float32)
        x = cv2.GaussianBlur(x, (0, 0), DOG_SIGMAS[0]) - cv2.GaussianBlur(x, (0, 0), DOG_SIGMAS[1])
        lo, hi = np.percentile(x, 1), np.percentile(x, 99)
        return np.clip((x - lo) * 255 / max(hi - lo, 1e-6), 0, 255).astype(np.uint8)
    clahe = cv2.createCLAHE(clipLimit=2.0, tileGridSize=(4, 4))
    return clahe.apply(u8)


# ---------------- dense masked NCC ----------------
def _xcorr(f, g):
    F = np.fft.rfft2(f, (PH, PW)); G = np.fft.rfft2(g, (PH, PW))
    return np.fft.fftshift(np.fft.irfft2(F * np.conj(G), (PH, PW)))


def masked_ncc_map(a, ma, b, mb):
    N = _xcorr(ma, mb)
    Nc = np.maximum(N, 1)
    Sa = _xcorr(a * ma, mb); Sb = _xcorr(ma, b * mb)
    Sab = _xcorr(a * ma, b * mb)
    Saa = _xcorr(a * a * ma, mb); Sbb = _xcorr(ma, b * b * mb)
    num = Sab - Sa * Sb / Nc
    da = np.maximum(Saa - Sa * Sa / Nc, 1e-6); db = np.maximum(Sbb - Sb * Sb / Nc, 1e-6)
    return num / np.sqrt(da * db), N


def _rotate(img, ang, mask):
    M = cv2.getRotationMatrix2D((W / 2, AH / 2), ang, 1.0)
    r = cv2.warpAffine(img, M, (W, AH), flags=cv2.INTER_LINEAR, borderMode=cv2.BORDER_CONSTANT, borderValue=0.0)
    m = cv2.warpAffine(mask, M, (W, AH), flags=cv2.INTER_NEAREST, borderMode=cv2.BORDER_CONSTANT, borderValue=0)
    return r, m


_WIN = {}


def _window(maxshift):
    w = _WIN.get(maxshift)
    if w is None:
        w = np.zeros((PH, PW), bool)
        cy, cx = PH // 2, PW // 2
        w[cy - maxshift:cy + maxshift + 1, cx - maxshift:cx + maxshift + 1] = True
        _WIN[maxshift] = w
    return w


def dense_score(a_u8, b_u8, cfg, mask=None, angles=None):
    """Best masked NCC of template b (rotated/shifted) onto probe a.
    Returns (ncc, angle_deg, dy, dx, overlap_px)."""
    a = a_u8.astype(np.float32) / 255.0
    bf = b_u8.astype(np.float32) / 255.0
    ma = _ONES if mask is None else mask
    win = _window(cfg["max_shift"])
    best = (-1.0, 0, 0, 0, 0)
    if angles is None:
        angles = range(-cfg["max_angle"], cfg["max_angle"] + 1, cfg["angle_step"])
    for ang in angles:
        rb, mb = _rotate(bf, ang, ma)
        nmap, N = masked_ncc_map(a, ma, rb, mb)
        ok = win & (N >= cfg["min_overlap_px"])
        if ok.any():
            v = np.where(ok, nmap, -2.0)
            k = np.unravel_index(int(v.argmax()), v.shape)
            if v[k] > best[0]:
                best = (float(v[k]), int(ang), int(k[0] - PH // 2), int(k[1] - PW // 2), int(N[k]))
    return best


def near_identity(r):
    return abs(r[1]) < 2 and abs(r[2]) < 2 and abs(r[3]) < 2


def passes(cfg, r):
    ncc, _, _, _, ov = r
    if ov < cfg["min_overlap_px"] or ncc < cfg["pass_ncc"]:
        return False
    if near_identity(r) and ncc < cfg["identity_veto_ncc"]:
        return False
    return True


def _batch_ncc(a, ma, rb, mb, win, min_overlap):
    """Masked NCC maps for a batch of rotated templates (rb, mb: (N,AH,W)) against probe a.
    Returns per-item (best_ncc, dy, dx, overlap)."""
    FA = np.fft.rfft2(a * ma, (PH, PW)); FM = np.fft.rfft2(ma, (PH, PW)); FAA = np.fft.rfft2(a * a * ma, (PH, PW))
    GM = np.conj(np.fft.rfft2(mb, (PH, PW))); GB = np.conj(np.fft.rfft2(rb * mb, (PH, PW))); GBB = np.conj(np.fft.rfft2(rb * rb * mb, (PH, PW)))
    sh = lambda x: np.fft.fftshift(np.fft.irfft2(x, (PH, PW)), axes=(-2, -1))
    N = sh(FM * GM)
    Nc = np.maximum(N, 1)
    Sa = sh(FA * GM); Sb = sh(FM * GB); Sab = sh(FA * GB); Saa = sh(FAA * GM); Sbb = sh(FM * GBB)
    num = Sab - Sa * Sb / Nc
    da = np.maximum(Saa - Sa * Sa / Nc, 1e-6); db = np.maximum(Sbb - Sb * Sb / Nc, 1e-6)
    ncc = num / np.sqrt(da * db)
    ok = win[None] & (N >= min_overlap)
    ncc = np.where(ok, ncc, -2.0)
    flat = ncc.reshape(ncc.shape[0], -1)
    idx = flat.argmax(axis=1)
    vals = flat[np.arange(len(idx)), idx]
    dy, dx = np.unravel_index(idx, (PH, PW))
    ov = N.reshape(N.shape[0], -1)[np.arange(len(idx)), idx]
    return vals, dy - PH // 2, dx - PW // 2, ov


def _rotations(templates_f, mask, angles):
    rb = np.empty((len(templates_f) * len(angles), AH, W), np.float32)
    mb = np.empty_like(rb)
    k = 0
    for t in templates_f:
        for ang in angles:
            rb[k], mb[k] = _rotate(t, ang, mask)
            k += 1
    return rb, mb


def best_vs_templates(cfg, probe_u8, templates_u8, mask=None, refine_top=4):
    """Batched coarse-to-fine search: all templates x coarse angles in one FFT batch, then the best
    few templates refined at the full angle step. Returns (ncc, angle, dy, dx, overlap)."""
    if not templates_u8:
        return (-1.0, 0, 0, 0, 0)
    a = probe_u8.astype(np.float32) / 255.0
    ma = _ONES if mask is None else mask
    win = _window(cfg["max_shift"])
    tf = [t.astype(np.float32) / 255.0 for t in templates_u8]
    step = cfg["angle_step"]
    coarse = list(range(-cfg["max_angle"], cfg["max_angle"] + 1, 2 * step))
    chunk = 8                                       # templates per FFT batch (bounded memory)
    per_t = np.empty((len(tf), len(coarse)), np.float64)
    for c0 in range(0, len(tf), chunk):
        rb, mb = _rotations(tf[c0:c0 + chunk], ma, coarse)
        vals, _, _, _ = _batch_ncc(a, ma, rb, mb, win, cfg["min_overlap_px"])
        per_t[c0:c0 + chunk] = vals.reshape(-1, len(coarse))
    best_ang_idx = per_t.argmax(axis=1)
    order = np.argsort(-per_t.max(axis=1))[:refine_top]
    best = (-1.0, 0, 0, 0, 0)
    fine_sets = []
    for i in order:
        a0 = coarse[best_ang_idx[i]]
        fine = [x for x in range(a0 - 2 * step, a0 + 2 * step + 1, step) if -cfg["max_angle"] <= x <= cfg["max_angle"]]
        fine_sets.append((i, fine))
    rb2, mb2 = [], []
    for i, fine in fine_sets:
        r, m = _rotations([tf[i]], ma, fine); rb2.append(r); mb2.append(m)
    rb2 = np.concatenate(rb2); mb2 = np.concatenate(mb2)
    vals2, dy2, dx2, ov2 = _batch_ncc(a, ma, rb2, mb2, win, cfg["min_overlap_px"])
    k = 0
    for i, fine in fine_sets:
        for ang in fine:
            if vals2[k] > best[0]:
                best = (float(vals2[k]), int(ang), int(dy2[k]), int(dx2[k]), int(ov2[k]))
            k += 1
    return best


def best_vs_templates_serial(cfg, probe_u8, templates_u8, mask=None, refine_top=4):
    """Coarse-to-fine: every template at 2x the angle step, then the best few refined at full
    resolution around their coarse angle. ~3x faster than exhaustive, same maxima in practice."""
    step = cfg["angle_step"]
    coarse = range(-cfg["max_angle"], cfg["max_angle"] + 1, 2 * step)
    scored = []
    for i, t in enumerate(templates_u8):
        r = dense_score(probe_u8, t, cfg, mask, coarse)
        scored.append((r[0], i, r))
        if r[0] >= cfg.get("single_frame_ncc", 1.1):
            break                                   # decisive already
    scored.sort(key=lambda x: -x[0])
    best = (-1.0, 0, 0, 0, 0)
    for _, i, r in scored[:refine_top]:
        a0 = r[1]
        fine = [a for a in range(a0 - 2 * step, a0 + 2 * step + 1, step) if -cfg["max_angle"] <= a <= cfg["max_angle"]]
        rf = dense_score(probe_u8, templates_u8[i], cfg, mask, fine)
        if rf[0] > best[0]:
            best = rf
    return best


# ---------------- enrollment container ----------------
class Enrollment:
    """Everything the matcher needs for one user, kept in memory.
    raw templates are float32 (finger - background) frames; images are derived on load so the
    preprocessing variant can change without re-enrolling."""

    def __init__(self, cfg, templates_raw=(), bg=None, noise=None, dac=None, gain=None, variant=None):
        self.cfg = cfg
        self.templates_raw = [np.asarray(t, np.float32) for t in templates_raw]
        self.bg = None if bg is None else np.asarray(bg, np.float32)
        self.noise = None if noise is None or np.size(noise) == 0 else np.asarray(noise, np.float32)
        self.dac = int(dac) if dac is not None else cfg["dac"]
        self.variant = variant or cfg["preprocess"]
        self.gain = sanitize_gain(gain)
        self._images = None

    @property
    def images(self):
        if self._images is None:
            self._images = [preprocess_diff(t, self.gain, self.variant) for t in self.templates_raw]
        return self._images

    def preprocess(self, diff):
        return preprocess_diff(diff, self.gain, self.variant)

    def add_template(self, diff):
        self.templates_raw.append(np.asarray(diff, np.float32))
        self._images = None

    def rebuild_gain(self):
        self.gain = build_gain_map(self.templates_raw, self.cfg["gain_map_min_frames"])
        self._images = None

    def to_npz_dict(self):
        return {
            "templates": np.stack(self.templates_raw) if self.templates_raw else np.zeros((0, AH, W), np.float32),
            "bg": self.bg if self.bg is not None else np.zeros((0,), np.float32),
            "noise": self.noise if self.noise is not None else np.zeros((0,), np.float32),
            "gain": self.gain if self.gain is not None else np.zeros((0,), np.float32),
            "dac": np.array(self.dac), "variant": np.array(self.variant),
        }

    @classmethod
    def from_npz(cls, cfg, z):
        return cls(cfg, templates_raw=list(z["templates"]), bg=z["bg"] if z["bg"].size else None,
                   noise=z["noise"], dac=int(z["dac"]), gain=z["gain"], variant=str(z["variant"]))
