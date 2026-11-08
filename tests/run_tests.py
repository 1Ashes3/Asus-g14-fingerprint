#!/usr/bin/env python3
"""Offline tests (no sensor needed). Run:  <venv>/bin/python -I tests/run_tests.py
Uses the V1.0 saved captures when present for matcher parity; skips otherwise."""
import glob
import io
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
import numpy as np  # noqa: E402

from asus_fp import config as cfgmod, matcher, store, installer, sensor  # noqa: E402

CAPTURES = os.environ.get("ASUS_FP_CAPTURES", os.path.join(os.path.dirname(ROOT), "versions", "prototype_V0.0", "tools", "captures", "session"))


def load_raw(p):
    return np.frombuffer(open(p, "rb").read(), dtype="<u2").astype(np.float32).reshape(60, 64)


class Decode(unittest.TestCase):
    def test_12bit_unpack_matches_reference(self):
        sys.path.insert(0, os.path.join(ROOT, "third_party", "goodix_fp_dump"))
        import tool
        data = os.urandom(7680)
        ref = np.array(tool.decode_image(data), dtype=np.uint16)
        self.assertTrue(np.array_equal(sensor.decode_12bit(data), ref))


class Matcher(unittest.TestCase):
    @unittest.skipUnless(os.path.isdir(CAPTURES), "saved captures not available")
    def test_parity_with_v1(self):
        cfg = dict(cfgmod.DEFAULTS)
        def ses(ts, lab):
            bg = load_raw(f"{CAPTURES}/{ts}_bg_m01_d107.raw")
            return [load_raw(f) - bg for f in sorted(glob.glob(f"{CAPTURES}/{ts}_f{lab}_p*_m01_d107.raw"))]
        A, Ao, B = ses("201454", "A"), ses("201001", "A"), ses("201001", "B")
        gain = matcher.build_gain_map(A + Ao + B, 12)
        enr = matcher.Enrollment(cfg, templates_raw=A, gain=gain)
        tpl = enr.images
        imp = max(matcher.best_vs_templates(cfg, enr.preprocess(d), tpl)[0] for d in B)
        gen = min(matcher.best_vs_templates(cfg, enr.preprocess(d), tpl)[0] for d in Ao)
        self.assertLess(imp, cfg["pass_ncc"], f"impostor max {imp:.3f} must stay below pass threshold")
        self.assertGreater(gen, 0.74, f"cross-session genuine min {gen:.3f} regressed")
        self.assertEqual(sum(matcher.passes(cfg, matcher.best_vs_templates(cfg, enr.preprocess(d), tpl)) for d in B), 0)

    def test_enrollment_roundtrip(self):
        cfg = dict(cfgmod.DEFAULTS)
        t = [np.random.RandomState(i).normal(-1900, 150, (60, 64)).astype(np.float32) for i in range(3)]
        e = matcher.Enrollment(cfg, templates_raw=t, bg=np.full((60, 64), 3900, np.float32), dac=0x110)
        buf = io.BytesIO(); np.savez(buf, **e.to_npz_dict()); buf.seek(0)
        e2 = matcher.Enrollment.from_npz(cfg, np.load(buf))
        self.assertEqual(len(e2.templates_raw), 3); self.assertEqual(e2.dac, 0x110); self.assertEqual(e2.variant, "clahe")
        self.assertEqual(e2.images[0].shape, (60, 64))

    def test_identity_veto(self):
        cfg = dict(cfgmod.DEFAULTS)
        self.assertFalse(matcher.passes(cfg, (0.85, 0, 0, 0, 3000)))      # near-identity below veto
        self.assertTrue(matcher.passes(cfg, (0.95, 0, 0, 0, 3000)))
        self.assertTrue(matcher.passes(cfg, (0.80, 6, 5, -8, 2000)))
        self.assertFalse(matcher.passes(cfg, (0.80, 6, 5, -8, 1000)))      # overlap too small


ARCH_VENDOR = """#%PAM-1.0

auth       required                    pam_shells.so
auth       requisite                   pam_nologin.so
auth       requisite                   pam_faillock.so      preauth
-auth      required                    pam_fprintd.so
auth       optional                    pam_permit.so
auth       required                    pam_env.so

account    include                     system-local-login

password   required                    pam_deny.so

session    include                     system-local-login
"""
DEBIAN_STYLE = """#%PAM-1.0
auth	required	pam_fprintd.so
@include common-account
@include common-session
"""


class PamDerivation(unittest.TestCase):
    def derive_from(self, text):
        with tempfile.NamedTemporaryFile("w", suffix="kde-fingerprint", delete=False) as f:
            f.write(text); path = f.name
        old = installer.VENDOR_PAM_PATHS, installer.PAM_FILE
        installer.VENDOR_PAM_PATHS, installer.PAM_FILE = [path], "/nonexistent/kde-fingerprint"
        try:
            return installer.derive_pam("/opt/asus-fingerprint/bin/asus-fp-pam")
        finally:
            installer.VENDOR_PAM_PATHS, installer.PAM_FILE = old
            os.remove(path)

    def test_arch_vendor(self):
        out = self.derive_from(ARCH_VENDOR)
        self.assertNotIn("pam_fprintd", out)
        self.assertIn("pam_exec.so          quiet stdout /opt/asus-fingerprint/bin/asus-fp-pam", out)
        self.assertIn("managed by asus-fingerprint", out)
        self.assertIn("system-local-login", out)
        self.assertEqual(out.count("pam_exec.so"), 1)

    def test_debian_style(self):
        out = self.derive_from(DEBIAN_STYLE)
        self.assertNotIn("pam_fprintd", out); self.assertIn("@include common-account", out); self.assertEqual(out.count("pam_exec.so"), 1)

    def test_no_fprintd_line_inserts_ours(self):
        out = self.derive_from(ARCH_VENDOR.replace("-auth      required                    pam_fprintd.so\n", ""))
        self.assertEqual(out.count("pam_exec.so"), 1)
        lines = [l for l in out.splitlines() if l.startswith(("auth", "-auth"))]
        self.assertTrue(any("pam_exec" in l for l in lines))


class Store(unittest.TestCase):
    def test_names(self):
        self.assertTrue(store.valid_user("alice")); self.assertFalse(store.valid_user("../x")); self.assertFalse(store.valid_user("A B"))
        with self.assertRaises(ValueError):
            store.cred_path("../etc")

    def test_dropin_lists_enrolled_users(self):
        with tempfile.TemporaryDirectory() as d:
            old = store.VAR_DIR, store.DROPIN_DIR, store.DROPIN
            store.VAR_DIR, store.DROPIN_DIR, store.DROPIN = d, os.path.join(d, "dropin"), os.path.join(d, "dropin", "10.conf")
            try:
                open(os.path.join(d, "alice.cred"), "wb").close(); open(os.path.join(d, "bob.npz"), "wb").close()
                open(os.path.join(d, "..evil.cred"), "wb").close()
                store.write_dropin()
                txt = open(store.DROPIN).read()
                self.assertIn(f"LoadCredentialEncrypted=enroll-alice:{d}/alice.cred", txt)
                self.assertIn(f"LoadCredential=enroll-bob:{d}/bob.npz", txt)
                self.assertNotIn("evil", txt)
            finally:
                store.VAR_DIR, store.DROPIN_DIR, store.DROPIN = old

    @unittest.skipUnless(os.getuid() == 0 and store.creds_supported(), "system credential round trip needs root")
    def test_system_credential_roundtrip(self):
        data = b"secret enrollment bytes " * 100
        blob = store.encrypt_system(data, "enroll-test")
        self.assertEqual(store.decrypt_system(blob, "enroll-test"), data)


class Compact(unittest.TestCase):
    def test_100_templates_fit_credential_limit(self):
        rng = np.random.RandomState(1)
        arrays = {"templates": rng.normal(-1900, 300, (100, 60, 64)).astype(np.float32),
                  "bg": np.full((60, 64), 3900, np.float32), "noise": np.zeros((0,), np.float32),
                  "gain": np.ones((60, 64), np.float32), "dac": np.array(0x10b), "variant": np.array("clahe")}
        data = store.compact_bytes(arrays)
        self.assertLessEqual(len(data), store.CRED_MAX)
        z = store.load_npz(data)
        self.assertEqual(z["templates"].shape[0], 100)
        self.assertLessEqual(float(np.abs(z["templates"].astype(np.float32) - arrays["templates"]).max()), 0.5)
        e = matcher.Enrollment.from_npz(dict(cfgmod.DEFAULTS), z)
        self.assertEqual(e.templates_raw[0].dtype, np.float32)

    def test_oversize_drops_oldest(self):
        old = store.CRED_MAX
        store.CRED_MAX = 200 * 1024
        try:
            rng = np.random.RandomState(2)
            arrays = {"templates": rng.normal(0, 3000, (60, 60, 64)).astype(np.float32), "bg": np.zeros((60, 64), np.float32),
                      "noise": np.zeros((0,), np.float32), "gain": np.zeros((0,), np.float32), "dac": np.array(0x107), "variant": np.array("clahe")}
            data = store.compact_bytes(arrays)
            self.assertLessEqual(len(data), store.CRED_MAX)
            z = store.load_npz(data)
            self.assertLess(z["templates"].shape[0], 60)
            self.assertTrue(np.array_equal(z["templates"][-1], np.rint(arrays["templates"][-1]).astype(np.int16)))
        finally:
            store.CRED_MAX = old


class Hardware(unittest.TestCase):
    def test_check_shape(self):
        from asus_fp import hardware
        r = hardware.check()
        self.assertIn("ok", r); self.assertIsInstance(r["problems"], list)
        self.assertEqual(r["ok"], not r["problems"])
        self.assertTrue(hardware.summary(r))

    def test_missing_sensor_is_a_problem(self):
        from asus_fp import hardware
        old = hardware.find_sensor
        hardware.find_sensor = lambda: None
        try:
            r = hardware.check()
            self.assertFalse(r["ok"]); self.assertTrue(any("27c6" in p for p in r["problems"]))
        finally:
            hardware.find_sensor = old


class Service(unittest.TestCase):
    """Runs the real daemon on a private socket with a fake (plaintext) enrollment; no sensor access."""

    @classmethod
    def setUpClass(cls):
        import json as _j, pwd as _p, socket as _s, time as _t
        cls.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(cls.tmp, "creds")); os.makedirs(os.path.join(cls.tmp, "run"))
        cls.user = _p.getpwuid(os.getuid()).pw_name
        e = matcher.Enrollment(dict(cfgmod.DEFAULTS), templates_raw=[np.zeros((60, 64), np.float32) - 1900],
                               bg=np.full((60, 64), 3900, np.float32), dac=0x10b)
        open(os.path.join(cls.tmp, "creds", f"enroll-{cls.user}"), "wb").write(store.npz_bytes(e.to_npz_dict()))
        env = dict(os.environ, ASUS_FP_RUN_DIR=os.path.join(cls.tmp, "run"), CREDENTIALS_DIRECTORY=os.path.join(cls.tmp, "creds"))
        cls.proc = subprocess.Popen([sys.executable, "-I", os.path.join(ROOT, "run.py"), "daemon"], env=env,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        cls.sock = os.path.join(cls.tmp, "run", "sock")
        for _ in range(100):
            if os.path.exists(cls.sock):
                break
            _t.sleep(0.1)

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate(); cls.proc.wait(5)
        import shutil as _sh; _sh.rmtree(cls.tmp, ignore_errors=True)

    def req(self, raw):
        import socket as _s, json as _j
        s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM); s.settimeout(10); s.connect(self.sock)
        s.sendall(raw if isinstance(raw, bytes) else (_j.dumps(raw) + "\n").encode())
        data = b""
        try:
            while not data.endswith(b"\n"):
                c = s.recv(4096)
                if not c:
                    break
                data += c
        finally:
            s.close()
        return _j.loads(data.decode().splitlines()[-1]) if data.strip() else None

    def test_status(self):
        r = self.req({"cmd": "status", "user": self.user})
        self.assertEqual(r["enrolled"], 1)
        self.assertNotIn("ncc", r)

    def test_score_and_calibration_removed(self):
        self.assertEqual(self.req({"cmd": "score", "user": self.user, "diff": "AAAA"}), {"error": "unknown command"})
        self.assertEqual(self.req({"cmd": "calibration", "user": self.user}), {"error": "unknown command"})

    def test_malformed_requests_do_not_kill_service(self):
        for raw in (b"[1]\n", b"null\n", b"{\"cmd\": 5, \"user\": []}\n", b"not json\n",
                    b'{"cmd":"verify","user":"%s","timeout":[1]}\n' % self.user.encode(),
                    b'{"cmd":"enroll","user":"%s","presses":7}\n' % self.user.encode()):
            try:
                self.req(raw)
            except Exception:
                pass
        self.assertIsNone(self.proc.poll(), "service died on a malformed request")
        self.assertEqual(self.req({"cmd": "status", "user": self.user})["enrolled"], 1)

    def test_other_user_rejected(self):
        self.assertEqual(self.req({"cmd": "status", "user": "root"}), {"error": "not permitted"})



if __name__ == "__main__":
    unittest.main(verbosity=2)
