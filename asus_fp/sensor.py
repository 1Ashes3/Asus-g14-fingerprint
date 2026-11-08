"""Sensor session for the Goodix 27c6:521d: USB protocol (vendored goodix-fp-dump), in-process
TLS-PSK decryption of image frames (Python ssl + MemoryBIO, no OpenSSL subprocess, no sockets),
background / noise-mask handling and finger detection.

Only the capture path lives here; it never erases, flashes or writes the PSK (see firmware.py)."""
import fcntl
import os
import ssl
import time

import numpy as np

from . import config as cfgmod
from .vendor import goodix, protocol, c52

W, H, AROW = 64, 80, 20          # raw frame 64x80, first 20 rows are dummy
AH = H - AROW                    # active 64x60
DEAD_COL = 22
VID, PID = 0x27C6, 0x521D
FRAME_BYTES = 7684               # decrypted image record: 5120 px * 12 bit + 4 trailing bytes


class SensorBusy(RuntimeError):
    pass


LOCK_PATH = "/run/asus-fp/sensor.lock"


def acquire_lock():
    """Exclusive, non-blocking lock shared by the service and the root flasher. The service creates
    /run/asus-fp/sensor.lock (0644); others open it read-only (flock works on read-only fds)."""
    if os.path.exists(LOCK_PATH):
        f = open(LOCK_PATH, "r")
    elif os.path.isdir(os.path.dirname(LOCK_PATH)) and os.access(os.path.dirname(LOCK_PATH), os.W_OK):
        f = open(LOCK_PATH, "a")
    else:                                         # no service yet (e.g. before install): private lock
        d = os.environ.get("XDG_RUNTIME_DIR") or ("/run" if os.getuid() == 0 else f"/tmp/asus-fp-{os.getuid()}")
        os.makedirs(d, mode=0o700, exist_ok=True)
        f = open(os.path.join(d, "asus-fp-sensor.lock"), "a")
    try:
        fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        f.close()
        raise SensorBusy("fingerprint sensor is in use by another process")
    return f


def release_lock(f):
    try:
        fcntl.flock(f, fcntl.LOCK_UN)
    except OSError:
        pass
    f.close()


class SensorError(RuntimeError):
    pass


class TlsLink:
    """TLS 1.2 PSK server terminated in memory. The sensor is the TLS client; bytes travel over USB."""

    def __init__(self, psk: bytes):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
        ctx.set_ciphers("PSK:@SECLEVEL=0")
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.set_psk_server_callback(lambda identity: psk)
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.obj = ctx.wrap_bio(self.incoming, self.outgoing, server_side=True)

    def _pump_handshake(self):
        try:
            self.obj.do_handshake()
            return True
        except ssl.SSLWantReadError:
            return False

    def handshake(self, device):
        """Mirror of goodix-fp-dump tool.connect_device(): ClientHello from the device, one server
        flight back, three device records, final server flight."""
        self.incoming.write(device.request_tls_connection())
        done = self._pump_handshake()
        flight = self.outgoing.read()
        if not flight:
            raise SensorError("TLS: no ServerHello produced")
        device.protocol.write(goodix.encode_message_pack(flight, goodix.FLAGS_TRANSPORT_LAYER_SECURITY))
        for _ in range(3):
            self.incoming.write(goodix.check_message_pack(device.protocol.read(),
                                                          goodix.FLAGS_TRANSPORT_LAYER_SECURITY))
        done = self._pump_handshake()
        flight = self.outgoing.read()
        if flight:
            device.protocol.write(goodix.encode_message_pack(flight, goodix.FLAGS_TRANSPORT_LAYER_SECURITY))
        if not done:
            raise SensorError("TLS handshake did not complete")
        time.sleep(0.01)

    def decrypt(self, record: bytes) -> bytes:
        self.incoming.write(record)
        out = b""
        while True:
            try:
                chunk = self.obj.read(16384)
            except ssl.SSLWantReadError:
                break
            if not chunk:
                break
            out += chunk
        return out


class Sensor:
    """One open session on the sensor. Use as a context manager; holds an exclusive lock."""

    def __init__(self, cfg=None, log=print):
        self.c = cfg or cfgmod.DEFAULTS
        self.log = log
        self.bg = None
        self.noise = None
        self.mask = np.ones((AH, W), np.float32)
        self.mask[:, DEAD_COL] = 0
        self.mask_info = "no noise map"
        self._bright = 0
        self._lock = acquire_lock()
        try:
            self._open()
        except Exception:
            self.close()                         # dispose the USB handle too, or the next open gets EBUSY
            raise

    # ---- session setup ----
    def _open(self):
        self.device = goodix.Device(PID, protocol.USBProtocol)
        fw = None
        for _ in range(6):                       # discard stale replies from earlier sessions
            try:
                self.device.empty_buffer(); self.device.nop(); time.sleep(0.3); self.device.empty_buffer()
                fw = self.device.firmware_version(); break
            except ValueError:
                time.sleep(0.5)
        if fw != c52.TARGET_FIRMWARE:
            raise SensorError(f"unexpected firmware {fw!r} (expected {c52.TARGET_FIRMWARE}); run the firmware check")
        self.firmware = fw
        # The sensor only loads its pairing key for TLS after a PSK read; without this the first session
        # after a power cycle fails with "bad record mac" (community driver_52xd does the same check).
        r = self.device.preset_psk_read(0xBB020001, len(c52.PMK_HASH), 0)
        if not r[0] or r[1] != 0xBB020001 or r[2] != c52.PMK_HASH:
            raise SensorError("sensor pairing key is not the community key - re-run the firmware flash")
        if not self.device.reset(True, False, 20)[0]:
            raise SensorError("sensor reset failed")
        self.device.read_sensor_register(0x0000, 4)
        self.device.read_otp()
        self.tls = TlsLink(c52.PSK)
        self.tls.handshake(self.device)
        if not self.device.upload_config_mcu(c52.DEVICE_CONFIG):
            raise SensorError("config upload failed")
        self.device.set_drv_state()
        self.device.mcu_get_pov_image()
        fdt0 = b"\x0d\x01\x27\x01\x21\x01\x27\x01\x23\x01" + b"\x00" * 16
        self.device.mcu_switch_to_fdt_mode(fdt0 + b"\x00", False)
        self.device.mcu_switch_to_fdt_mode(fdt0 + b"\x01", True)
        self.set_dac(self.c["dac"])

    def set_dac(self, dac):
        self.dac = int(dac)
        self.payload = bytes([self.c["mode"], 0x03]) + b"".join(
            (self.dac + o).to_bytes(2, "little") for o in self.c["dac_offsets"])

    def _release(self):
        release_lock(self._lock)

    def close(self):
        if getattr(self, "_closed", False):
            return
        self._closed = True
        try:
            dev = getattr(self, "device", None)
            if dev is not None:
                try:
                    import usb.util
                    usb.util.dispose_resources(dev.protocol.device)
                except Exception:
                    pass
        finally:
            self.device = None
            import gc
            gc.collect()                         # drop any half-constructed pyusb handle (EBUSY otherwise)
            self._release()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # ---- frames ----
    def frame(self):
        """One raw active-area frame as float32 (60, 64), 12-bit values."""
        d = self.device
        d.write_sensor_register(0x022c, b"\x0a\x03")
        reply = d.mcu_get_image(self.payload, goodix.FLAGS_TRANSPORT_LAYER_SECURITY_DATA)
        data = self.tls.decrypt(bytes(reply[9:]))
        d.write_sensor_register(0x022c, b"\x0a\x02")
        if len(data) < FRAME_BYTES:
            raise SensorError(f"short decrypted image ({len(data)} bytes)")
        px = decode_12bit(data[:FRAME_BYTES - 4])
        return px.reshape(H, W)[AROW:].astype(np.float32)

    def take_background(self, n=None, progress=None):
        n = n or self.c["bg_frames"]
        frames = []
        for i in range(n):
            frames.append(self.frame())
            if progress and (i + 1) % 10 == 0:
                progress(i + 1, n)
        stack = np.stack(frames)
        self.bg = stack.mean(axis=0)
        self.noise = stack.std(axis=0) if n >= 10 else None
        self.build_mask()
        self._bright = 0

    def set_background(self, bg, noise=None):
        self.bg = np.asarray(bg, np.float32)
        self.noise = None if noise is None or np.size(noise) == 0 else np.asarray(noise, np.float32)
        self.build_mask()

    def build_mask(self):
        m = np.ones((AH, W), np.float32)
        m[:, DEAD_COL] = 0
        if self.noise is not None:
            med = float(np.median(self.noise))
            bad = self.noise > max(self.c["noise_mask_factor"] * med, self.c["noise_floor"])
            m[bad] = 0
            self.mask_info = f"median noise {med:.1f}, masked {int(bad.sum())} px"
        else:
            self.mask_info = "no noise map"
        self.mask = m

    def live(self):
        """Capture one frame; returns (finger_present, diff, offset, quality).
        diff = frame - background (float32). A finger only lowers readings; if frames stay much
        brighter than the background the background was taken with a finger on -> re-baseline."""
        if self.bg is None:
            raise SensorError("no background")
        f = self.frame()
        diff = f - self.bg
        offset = float(diff.mean())
        if offset > -self.c["finger_threshold"]:
            self._bright += 1
            if self._bright >= 3:
                self.bg = f.copy(); self._bright = 0
                self.log("background re-baselined (had been taken with a finger present)")
                diff = f - self.bg; offset = 0.0
        else:
            self._bright = 0
        finger = offset < self.c["finger_threshold"]
        q = ridge_ac(detrend(diff)) if finger else 0.0
        return finger, diff, offset, q

    def wait_finger(self, present, timeout, on_frame=None):
        """Block until finger presence == present (or timeout). Returns (ok, last_live_tuple)."""
        t0 = time.time()
        last = None
        while time.time() - t0 < timeout:
            last = self.live()
            if on_frame:
                on_frame(*last)
            if last[0] == present:
                return True, last
        return False, last


# ---- helpers (numpy versions of goodix-fp-dump tool.decode_image and the quality metric) ----
def decode_12bit(data: bytes) -> np.ndarray:
    b = np.frombuffer(data, dtype=np.uint8)
    b = b[: len(b) // 6 * 6].reshape(-1, 6).astype(np.uint16)
    p0 = ((b[:, 0] & 0xF) << 8) + b[:, 1]
    p1 = (b[:, 3] << 4) + (b[:, 0] >> 4)
    p2 = ((b[:, 5] & 0xF) << 8) + b[:, 2]
    p3 = (b[:, 4] << 4) + (b[:, 5] >> 4)
    return np.stack([p0, p1, p2, p3], axis=1).reshape(-1)


def detrend(v):
    return v - v.mean(axis=1, keepdims=True) - v.mean(axis=0, keepdims=True) + v.mean()


def ridge_ac(det):
    """Max autocorrelation along x at ridge-scale lags (3..12 px); ~0.3-0.5 for a finger, ~0 otherwise."""
    sd = det.std()
    if sd < 1e-6:
        return 0.0
    best = 0.0
    for lag in range(3, 13):
        best = max(best, float((det[:, :-lag] * det[:, lag:]).mean() / (sd * sd)))
    return best
