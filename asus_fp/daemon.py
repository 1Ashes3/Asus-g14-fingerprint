"""System fingerprint service (asus-fp.service, runs as user `asus-fp` from boot). V1.2: the service is the
ONLY non-root process that talks to the sensor (the udev rule no longer grants the desktop user access).

Enrollments arrive decrypted from systemd in $CREDENTIALS_DIRECTORY/enroll-<user> (LoadCredentialEncrypted=).
Socket: /run/asus-fp/sock. One JSON request per connection, newline-terminated; the peer's uid
(SO_PEERCRED) must be the named user (or root). Each connection runs in its own thread; sensor use is
serialised by a thread lock plus a file lock shared with the root flasher. Closing the connection
aborts any running operation.

Requests (no numeric match scores are ever returned to clients; they go to the journal only):
  {"cmd":"status","user":u}                         -> status object
  {"cmd":"firmware","user":u}                       -> {"state":..,"firmware":..}
  {"cmd":"verify","user":u,"timeout":s}             -> {"msg":..}* then {"result":"match"|"nomatch"|"error"}
  {"cmd":"test","user":u}                           -> events* then {"result":"match"|"nomatch"|"error"}
  {"cmd":"calibrate","user":u}                      -> events* then {"result":"calibrated"|"error"}
  {"cmd":"enroll","user":u,"presses":n,"append":b}  -> events* then {"result":"captured","new":n} | error
Events: {"state":"ON|OFF|WAIT|DONE|ERR","msg":..}, {"msg":..}, {"log":..},
        {"frame":{"finger":bool,"preview":b64 png-free u8 64x60}} (previews only during test/enroll)."""
import base64
import io
import json
import math
import os
import pwd
import select
import signal
import socket
import struct
import sys
import threading
import time

import numpy as np

from . import config as cfgmod

RUN_DIR = os.environ.get("ASUS_FP_RUN_DIR", "/run/asus-fp")
SOCK = os.path.join(RUN_DIR, "sock")
CRED_DIR = os.environ.get("CREDENTIALS_DIRECTORY", "")
MAX_CONNECTIONS = 8
PRESS_CHOICES = (5, 10, 20, 50)
TEST_WAIT_S = 60
OP_WAIT_S = 60


def log(msg):
    print(time.strftime("%H:%M:%S ") + msg, flush=True)


class Aborted(Exception):
    pass


class Conn:
    """Client connection helper: send events, detect disconnect."""

    def __init__(self, sock):
        self.s = sock

    def send(self, obj):
        self.s.sendall((json.dumps(obj) + "\n").encode())

    def gone(self):
        try:
            r, _, _ = select.select([self.s], [], [], 0)
            if r:
                return self.s.recv(1, socket.MSG_PEEK) == b""
        except OSError:
            return True
        return False

    def check(self):
        if self.gone():
            raise Aborted()


def preview(u8):
    return base64.b64encode(np.ascontiguousarray(u8, dtype=np.uint8).tobytes()).decode()


class Daemon:
    def __init__(self):
        self.cfg = cfgmod.load()
        self.enr = {}                 # user -> matcher.Enrollment (stored, from credentials)
        self.cal = {}                 # user -> dict(bg, noise, dac) from a Calibrate in this service run
        self.sensor_lock = threading.Lock()
        self.busy = False
        self.fw_cache = None
        self.slots = threading.BoundedSemaphore(MAX_CONNECTIONS)
        self.load_enrollments()

    # ---------------- enrollment loading ----------------
    def load_enrollments(self):
        from . import matcher
        self.enr = {}
        if not CRED_DIR or not os.path.isdir(CRED_DIR):
            log("no credentials directory - no enrollments loaded")
            return
        for name in sorted(os.listdir(CRED_DIR)):
            if not name.startswith("enroll-"):
                continue
            user = name[len("enroll-"):]
            try:
                with open(os.path.join(CRED_DIR, name), "rb") as f:
                    z = np.load(io.BytesIO(f.read()), allow_pickle=False)
                e = matcher.Enrollment.from_npz(self.cfg, z)
                _ = e.images
                self.enr[user] = e
                log(f"enrollment loaded for {user}: {len(e.templates_raw)} templates, dac 0x{e.dac:x}")
            except Exception as ex:
                log(f"failed to load enrollment for {user}: {ex!r}")

    # ---------------- sensor access ----------------
    def open_sensor(self, dac):
        """Returns an open Sensor or raises RuntimeError("busy"/...). Caller must close and release."""
        from .sensor import Sensor, SensorBusy
        if not self.sensor_lock.acquire(blocking=False):
            raise RuntimeError("sensor busy")
        try:
            c = dict(self.cfg); c["dac"] = dac
            s = Sensor(c, log=log)
        except SensorBusy:
            self.sensor_lock.release()
            raise RuntimeError("sensor busy")
        except Exception as ex:
            self.sensor_lock.release()
            log(f"sensor unavailable: {ex!r}")
            raise RuntimeError(f"sensor unavailable: {ex}")
        self.busy = True
        return s

    def close_sensor(self, s):
        try:
            s.close()
        finally:
            self.busy = False
            self.sensor_lock.release()

    def calibration_for(self, user):
        """(bg, noise, dac): session calibration if present, else the stored enrollment's."""
        if user in self.cal:
            c = self.cal[user]
            return c["bg"], c["noise"], c["dac"]
        e = self.enr.get(user)
        if e is not None and e.bg is not None:
            return e.bg, e.noise, e.dac
        return None, None, self.cfg["dac"]

    # ---------------- operations ----------------
    def op_verify(self, conn, user, timeout, previews=False):
        """Shared by PAM verify and the app's Test. Returns only match/nomatch to the client."""
        from . import matcher
        e = self.enr.get(user)
        if e is None or not e.templates_raw:
            conn.send({"result": "error", "detail": "no fingerprint enrolled"}); return
        try:
            s = self.open_sensor(e.dac)
        except RuntimeError as ex:
            conn.send({"result": "error", "detail": str(ex)}); return
        c = dict(self.cfg)
        try:
            if e.bg is not None:
                s.set_background(e.bg, e.noise)
            else:
                s.take_background()
            conn.send({"msg": "Fingerprint: touch the power button"})
            if previews:
                conn.send({"state": "ON", "msg": "place your finger on the power button and hold still"})
            deadline = time.time() + timeout
            attempts = 0
            images = e.images

            def on_frame(finger, diff, off, q):
                if previews:
                    conn.send({"frame": {"finger": bool(finger), "preview": preview(e.preprocess(diff))}})

            while time.time() < deadline:
                ok, _ = s.wait_finger(True, min(1.0, max(0.1, deadline - time.time())), on_frame=on_frame)
                conn.check()
                if not ok:
                    continue
                attempts += 1
                hits, best, seen = 0, 0.0, 0
                for _ in range(c["verify_max_frames"]):
                    finger, diff, off, q = s.live()
                    on_frame(finger, diff, off, q)
                    if not finger:
                        break
                    seen += 1
                    if seen <= c["verify_skip_frames"] or q < c["min_ridge_ac"]:
                        continue
                    r = matcher.best_vs_templates(c, e.preprocess(diff), images, s.mask)
                    best = max(best, r[0])
                    log(f"{'test' if previews else 'verify'} {user} frame {seen}: ncc {r[0]:.3f} angle {r[1]} shift ({r[2]},{r[3]}) overlap {r[4]}")
                    if matcher.passes(c, r):
                        hits += 1
                        if r[0] >= c["single_frame_ncc"] or hits >= c["frames_required"]:
                            log(f"MATCH user={user} attempt={attempts}")
                            conn.send({"msg": "Fingerprint recognised"})
                            conn.send({"result": "match"})
                            return
                    conn.check()
                log(f"no match for {user} (attempt {attempts}, best {best:.3f})")
                if previews:
                    conn.send({"result": "nomatch"}); return
                conn.send({"msg": "Fingerprint not recognised - try again" if best > 0 else "Hold the finger on the button a moment longer"})
                s.wait_finger(False, 10)
            conn.send({"result": "nomatch", "detail": f"timeout after {attempts} attempt(s)"})
        except Aborted:
            log(f"{'test' if previews else 'verify'} aborted: client disconnected")
        finally:
            self.close_sensor(s)

    def op_calibrate(self, conn, user):
        from . import calibrate as cal
        try:
            s = self.open_sensor(self.cfg["dac"])
        except RuntimeError as ex:
            conn.send({"result": "error", "detail": str(ex)}); return
        try:
            n = self.cfg["calib_frames"]
            conn.send({"state": "OFF", "msg": f"keep your finger OFF the sensor - calibrating ({n} blank frames, about a minute)"})
            time.sleep(1.5)
            conn.check()

            def progress(m):
                conn.send({"log": m}); conn.check()
            res = cal.calibrate(s, progress=progress)
            self.cal[user] = {"bg": res["bg"], "noise": res["noise"], "dac": res["dac"]}
            conn.send({"log": f"calibrated: DAC 0x{res['dac']:x}, blank mean {res['blank_mean']:.0f}, {res['mask_info']}"})
            conn.send({"state": "DONE", "msg": f"calibrated (DAC 0x{res['dac']:x})"})
            conn.send({"result": "calibrated"})
        except Aborted:
            log("calibrate aborted: client disconnected")
        finally:
            self.close_sensor(s)

    def op_enroll(self, conn, user, presses, append):
        from . import matcher
        uid = pwd.getpwnam(user).pw_uid
        stored = self.enr.get(user)
        if append:
            if stored is None or stored.bg is None:
                conn.send({"result": "error", "detail": "no stored enrollment to add to - use Enroll"}); return
            bg, noise, dac = stored.bg, stored.noise, stored.dac
        else:
            if user not in self.cal:
                conn.send({"result": "error", "detail": "calibrate first (Calibrate button), then enroll"}); return
            bg, noise, dac = self.cal[user]["bg"], self.cal[user]["noise"], self.cal[user]["dac"]
        enr = matcher.Enrollment(self.cfg, bg=bg, noise=noise, dac=dac,
                                 gain=stored.gain if append and stored else None)
        try:
            s = self.open_sensor(dac)
        except RuntimeError as ex:
            conn.send({"result": "error", "detail": str(ex)}); return
        c = self.cfg
        kept = 0
        try:
            s.set_background(bg, noise)
            images = list(stored.images) if append and stored else []

            def on_frame(finger, diff, off, q):
                conn.send({"frame": {"finger": bool(finger), "preview": preview(enr.preprocess(diff))}})

            cyc, retries = 1, 0
            while cyc <= presses:
                hint = "centre the fingertip on the button" if cyc == 1 else "a slightly different part of the fingertip"
                conn.send({"state": "ON", "msg": f"press {cyc}/{presses}: place and hold still ({hint})"})
                ok, _ = s.wait_finger(True, OP_WAIT_S, on_frame=on_frame)
                conn.check()
                if not ok:
                    conn.send({"result": "error", "detail": f"no finger detected within {OP_WAIT_S} s"}); return
                cands = []
                for _ in range(c["enroll_frames_per_cycle"]):
                    finger, diff, off, q = s.live()
                    on_frame(finger, diff, off, q)
                    if finger and q >= c["min_ridge_ac"]:
                        cands.append((q, diff))
                conn.check()
                if not cands:
                    conn.send({"state": "OFF", "msg": "no usable frame - lift and try again"})
                    s.wait_finger(False, 30); continue
                cands.sort(key=lambda t: -t[0])
                diff = cands[0][1]
                u8 = enr.preprocess(diff)
                best = matcher.best_vs_templates(c, u8, images, s.mask)[0] if images else -1.0
                log(f"enroll {user} press {cyc}: {len(cands)} usable frames, best vs existing {best:.3f}")
                if best >= c["new_area_ncc"] and retries < c["same_area_retries"]:
                    retries += 1
                    conn.send({"state": "OFF", "msg": "same area as an earlier press - lift and shift a little"})
                    s.wait_finger(False, 30); continue
                enr.add_template(diff); images.append(u8); kept += 1
                conn.send({"log": f"press {cyc} captured ({len(cands)} usable frames, quality {cands[0][0]:.2f})"})
                conn.send({"state": "OFF", "msg": f"press {cyc} captured - lift your finger"})
                s.wait_finger(False, 30)
                cyc += 1; retries = 0
                time.sleep(0.3)
        except Aborted:
            log("enroll aborted: client disconnected"); return
        finally:
            self.close_sensor(s)
        if kept == 0:
            conn.send({"result": "error", "detail": "nothing captured"}); return
        if not append:
            enr.rebuild_gain()
        self.write_pending(user, enr)
        conn.send({"result": "captured", "new": kept})

    def write_pending(self, user, enr):
        """Hand-off file for admin.py (root): only the service user can write it."""
        from . import store
        path = os.path.join(RUN_DIR, f"pending-{user}.npz")
        data = store.npz_bytes(enr.to_npz_dict())
        tmp = path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(data)
        os.replace(tmp, path)

    def op_firmware(self, conn):
        from . import firmware
        if not self.sensor_lock.acquire(blocking=False):
            conn.send(self.fw_cache or {"state": "busy", "firmware": "?"}); return
        try:
            self.fw_cache = firmware.probe()
        except Exception as ex:
            self.fw_cache = {"state": "error", "firmware": "?", "detail": str(ex)[:120]}
        finally:
            self.sensor_lock.release()
        conn.send(self.fw_cache)

    # ---------------- request handling ----------------
    def handle(self, sock):
        conn = Conn(sock)
        try:
            creds = sock.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
            _pid, peer_uid, _gid = struct.unpack("3i", creds)
            sock.settimeout(5)
            buf = b""
            while not buf.endswith(b"\n") and len(buf) < 4096:
                chunk = sock.recv(1024)
                if not chunk:
                    break
                buf += chunk
            sock.settimeout(None)
            req = json.loads(buf.decode() or "null")
            if not isinstance(req, dict):
                return
            cmd, user = req.get("cmd"), req.get("user")
            if not isinstance(cmd, str) or not isinstance(user, str):
                conn.send({"error": "bad request"}); return
            try:
                uid = pwd.getpwnam(user).pw_uid
            except KeyError:
                conn.send({"error": "unknown user"}); return
            if peer_uid not in (uid, 0):
                conn.send({"error": "not permitted"}); return
            if cmd == "verify":
                t = req.get("timeout", self.cfg["pam_timeout_s"])
                if not isinstance(t, (int, float)) or not math.isfinite(t):
                    t = self.cfg["pam_timeout_s"]
                self.op_verify(conn, user, min(max(1.0, float(t)), float(self.cfg["pam_timeout_s"])))
            elif cmd == "test":
                self.op_verify(conn, user, TEST_WAIT_S, previews=True)
            elif cmd == "calibrate":
                self.op_calibrate(conn, user)
            elif cmd == "enroll":
                presses, append = req.get("presses", 5), req.get("append", False)
                if presses not in PRESS_CHOICES or not isinstance(append, bool):
                    conn.send({"error": "bad request"}); return
                self.op_enroll(conn, user, presses, append)
            elif cmd == "firmware":
                self.op_firmware(conn)
            elif cmd == "status":
                e = self.enr.get(user)
                conn.send({"enrolled": len(e.templates_raw) if e else 0, "dac": e.dac if e else None,
                           "variant": e.variant if e else None,
                           "has_stored_calibration": bool(e is not None and e.bg is not None),
                           "has_session_calibration": user in self.cal,
                           "sensor": "busy" if self.busy else "idle", "firmware": self.fw_cache})
            else:
                conn.send({"error": "unknown command"})
        except (OSError, Aborted):
            pass
        except Exception as ex:                      # never let a bad request kill the service
            log(f"request error: {ex!r}")
            try:
                conn.send({"error": "bad request"})
            except OSError:
                pass
        finally:
            try:
                sock.close()
            except OSError:
                pass
            self.slots.release()

    def serve(self):
        os.makedirs(RUN_DIR, exist_ok=True)
        lock = os.path.join(RUN_DIR, "sensor.lock")
        fd = os.open(lock, os.O_WRONLY | os.O_CREAT, 0o644)     # shared with the root flasher (O_RDONLY flock)
        os.fchmod(fd, 0o644); os.close(fd)
        if os.path.exists(SOCK):
            os.remove(SOCK)
        srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        srv.bind(SOCK)
        os.chmod(SOCK, 0o666)
        srv.listen(16)
        log(f"listening on {SOCK}; enrolled users: {sorted(self.enr)}")
        signal.signal(signal.SIGTERM, lambda *_: os._exit(0))
        signal.signal(signal.SIGHUP, lambda *_: self.load_enrollments())
        while True:
            sock, _ = srv.accept()
            if not self.slots.acquire(blocking=False):
                try:
                    sock.sendall(b'{"error": "too many connections"}\n'); sock.close()
                except OSError:
                    pass
                continue
            threading.Thread(target=self.handle, args=(sock,), daemon=True).start()


def main():
    Daemon().serve()


if __name__ == "__main__":
    main()
