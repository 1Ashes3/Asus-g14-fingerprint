"""ASUS Fingerprint app (Tk), V1.2: status, install/uninstall, firmware flash (guarded, as root),
calibrate / enroll / add more / test (performed by the asus-fp service), delete. Runs as the normal user;
it never opens the sensor itself, and never sees match scores or stored templates."""
import base64
import io
import json
import os
import pwd
import queue
import shutil
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from tkinter import messagebox, ttk

from . import config as cfgmod, firmware, hardware, store, theme

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))     # source or /opt tree
LOG_DIR = os.path.join(HERE, "logs") if os.access(HERE, os.W_OK) else os.path.join(
    os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"), "asus-fp")
LOG_PATH = os.path.join(LOG_DIR, time.strftime("app-%Y%m%d.log"))


LOGGING = {"enabled": False}


def flog(msg):
    """Append a timestamped line to the app log file (everything the app does and measures)."""
    if not LOGGING["enabled"]:
        return
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(time.strftime("%H:%M:%S ") + str(msg) + "\n")
    except OSError:
        pass
OPT = "/opt/asus-fingerprint"
RUN_DIR = os.path.join(os.environ.get("XDG_RUNTIME_DIR") or f"/run/user/{os.getuid()}", "asus-fp")
SOCK = "/run/asus-fp/sock"
COLORS = {"WAIT": ("#444444", "#dddddd"), "ON": ("#1e7d32", "#ffffff"), "OFF": ("#b3261e", "#ffffff"),
          "DONE": ("#1a4b8c", "#ffffff"), "ERR": ("#7a1fa2", "#ffffff")}
TITLES = {"WAIT": "WAIT", "ON": "FINGER ON", "OFF": "FINGER OFF", "DONE": "DONE", "ERR": "ERROR"}


def daemon_cmd(obj, timeout=5):
    obj = dict(obj); obj.setdefault("user", pwd.getpwuid(os.getuid()).pw_name)
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(SOCK)
        s.sendall((json.dumps(obj) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(4096)
            if not chunk:
                break
            data += chunk
        s.close()
        return json.loads(data.decode().splitlines()[-1]) if data.strip() else None
    except (OSError, ValueError):
        return None


def packaged_by():
    """Name of the package manager that owns the install (e.g. 'pacman'), or None for an app-managed install."""
    try:
        return open(os.path.join(OPT, ".packaged")).read().strip() or "package manager"
    except OSError:
        return None


def installed():
    try:
        return os.path.exists(os.path.join(OPT, "bin", "asus-fp-admin")) and \
            "managed by asus-fingerprint" in open("/etc/pam.d/kde-fingerprint").read()
    except OSError:
        return False


def service_state():
    r = subprocess.run(["systemctl", "is-active", "asus-fp.service"], capture_output=True, text=True)
    return r.stdout.strip() or "unknown"


def daemon_stream(obj, on_event, stop_flag=lambda: False, timeout=None):
    """Send one request and feed every JSON line to on_event until a 'result'/'error' arrives.
    Returns the final object (or None). Closing the socket (stop_flag) aborts the operation in the service."""
    obj = dict(obj); obj.setdefault("user", pwd.getpwuid(os.getuid()).pw_name)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(5)
        s.connect(SOCK)
        s.sendall((json.dumps(obj) + "\n").encode())
        s.settimeout(0.5)
        buf = b""
        t0 = time.time()
        while True:
            if stop_flag():
                return {"result": "stopped"}
            if timeout and time.time() - t0 > timeout:
                return {"result": "error", "detail": "timeout"}
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                continue
            if not chunk:
                return None
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    ev = json.loads(line.decode())
                except ValueError:
                    continue
                if "result" in ev or "error" in ev:
                    return ev
                on_event(ev)
    except OSError as e:
        return {"result": "error", "detail": f"service not reachable: {e}"}
    finally:
        s.close()


def os_pretty():
    try:
        for line in open("/etc/os-release"):
            if line.startswith("PRETTY_NAME="):
                return line.split("=", 1)[1].strip().strip('"')
    except OSError:
        pass
    return "unknown"


class App:
    def __init__(self):
        self.cfg = cfgmod.load()
        self.user = pwd.getpwuid(os.getuid()).pw_name
        self.q = queue.Queue()
        self.busy = False
        self.fw = {"state": "unknown", "firmware": "?"}
        self.prefs = self._load_prefs()
        LOGGING["enabled"] = bool(self.prefs.get("logging", False))
        self.hw = hardware.check()
        self.root = tk.Tk()
        self.root.title("ASUS Fingerprint")
        self.root.geometry("+60+40")
        self.root.minsize(760, 560)
        self._build()
        flog(f"=== app start pid {os.getpid()} src {HERE} cfg {json.dumps(self.cfg, sort_keys=True)}")
        self.logline(f"log file: {LOG_PATH}" if LOGGING["enabled"] else "file logging is off (Options… to enable)")
        self.root.after(100, self._tick)
        self.root.after(300, self.refresh)
        self.stop_flag = False

    # ---------- layout ----------
    def _build(self):
        top = ttk.Frame(self.root, padding=10); top.pack(fill="x")
        self.status_vars = {}
        grid = ttk.Frame(top); grid.pack(side="left", fill="x", expand=True)
        rows = [("Hardware", "hardware"), ("System", "system"), ("Plasma / service", "plasma"), ("Install", "install"),
                ("Sensor firmware", "firmware"), ("Enrollment", "enroll"), ("Protection", "protect")]
        for i, (label, key) in enumerate(rows):
            ttk.Label(grid, text=label + ":", width=16, anchor="e").grid(row=i, column=0, sticky="e", padx=(0, 6))
            v = tk.StringVar(value="…"); self.status_vars[key] = v
            ttk.Label(grid, textvariable=v, anchor="w", wraplength=520).grid(row=i, column=1, sticky="w")
        ttk.Button(top, text="Refresh", command=self.refresh).pack(side="right", anchor="n")

        bar = ttk.Frame(self.root, padding=(10, 0, 10, 6)); bar.pack(fill="x")
        self.buttons = {}
        for key, text, cmd in [("install", "Install", self.install), ("uninstall", "Uninstall", self.uninstall),
                               ("flash", "Flash firmware…", self.flash), ("calib", "Calibrate", self.calibrate),
                               ("enroll", "Enroll", lambda: self.enroll(False)),
                               ("more", "Add more", lambda: self.enroll(True)),
                               ("delete", "Delete enrollment", self.delete), ("test", "Test", self.test),
                               ("options", "Options…", self.options), ("stop", "Stop", self.stop)]:
            b = ttk.Button(bar, text=text, command=cmd); b.pack(side="left", padx=3); self.buttons[key] = b

        body = ttk.Frame(self.root, padding=10); body.pack(fill="both", expand=True)
        body.columnconfigure(0, weight=3, uniform="half"); body.columnconfigure(1, weight=2, uniform="half")
        body.rowconfigure(0, weight=1)
        self.panel = tk.Frame(body, padx=16, pady=12); self.panel.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        self.big = tk.Label(self.panel, text="READY", font=("Sans", 30, "bold")); self.big.pack(fill="x")
        self.msg = tk.Label(self.panel, text="", font=("Sans", 12), wraplength=360, justify="center"); self.msg.pack(fill="x", pady=(4, 0))
        self.flag = tk.Label(self.panel, text="is finger detected = ?", font=("Mono", 11, "bold")); self.flag.pack(fill="x", pady=(6, 0))
        self.result = tk.Label(self.panel, text="", font=("Sans", 18, "bold")); self.result.pack(side="bottom", fill="x", pady=(8, 0))
        self.view = tk.Label(self.panel, bd=0); self.view.pack(fill="both", expand=True, pady=(8, 0))
        self._last_u8 = None
        self.view.bind("<Configure>", lambda e: self._on_view_resize())
        self.panel.bind("<Configure>", lambda e: self.msg.configure(wraplength=max(200, e.width - 40)))
        self.set_state("WAIT", "")
        logf = ttk.Frame(body); logf.grid(row=0, column=1, sticky="nsew")
        self.log_lines = []
        self.easter = False
        self.log = tk.Canvas(logf, width=300, height=300, highlightthickness=1, bd=0)
        self.log.pack(fill="both", expand=True)
        self.log.bind("<Configure>", lambda e: self._redraw_log(rebuild_bg=True))
        self.apply_theme()

    def set_state(self, key, message=""):
        flog(f"STATE {key}: {message}")
        bg, fg = COLORS.get(key, COLORS["WAIT"])
        for w in (self.panel, self.big, self.msg, self.flag, self.view, self.result):
            w.configure(bg=bg)
        for w in (self.big, self.msg, self.flag):
            w.configure(fg=fg)
        self.big.configure(text=TITLES.get(key, key)); self.msg.configure(text=message)

    def logline(self, text):
        flog(text)
        self.log_lines.append(text)
        self.log_lines = self.log_lines[-200:]
        self._redraw_log()

    # ---------- theme + log canvas ----------
    def apply_theme(self):
        mode = "dark" if self.prefs.get("dark") else "light"
        self.pal = theme.apply(self.root, mode)
        self.log.configure(bg=self.pal["field"], highlightbackground=self.pal["border"])
        self._redraw_log(rebuild_bg=True)

    def _redraw_log(self, rebuild_bg=False):
        c = self.log
        w, h = max(c.winfo_width(), 50), max(c.winfo_height(), 50)
        if rebuild_bg or not hasattr(self, "_wm_key") or self._wm_key != (w, h, self.easter, self.pal["field"]):
            c.delete("wm")
            self._wm_key = (w, h, self.easter, self.pal["field"])
            if self.easter:
                from PIL import Image
                rgb = theme.fingerprint_watermark(w, h, self.pal["field"], self.pal["watermark"], self.pal["watermark_alpha"])
                buf = io.BytesIO(); Image.fromarray(rgb).save(buf, "PNG")
                self._wm_photo = tk.PhotoImage(data=base64.b64encode(buf.getvalue()).decode())
                c.create_image(0, 0, image=self._wm_photo, anchor="nw", tags="wm")
                c.tag_lower("wm")
        c.delete("txt")
        item = c.create_text(6, 4, anchor="nw", width=w - 12, font=("Mono", 9), fill=self.pal["field_fg"], tags="txt", text="")
        lines = list(self.log_lines)
        # show the newest lines that fit
        lo, hi = 0, len(lines)
        while lo < hi:
            mid = (lo + hi) // 2
            c.itemconfigure(item, text="\n".join(lines[mid:]))
            bb = c.bbox(item)
            if bb and bb[3] - bb[1] > h - 8:
                lo = mid + 1
            else:
                hi = mid
        c.itemconfigure(item, text="\n".join(lines[lo:]))

    def set_easter(self, on):
        if on != self.easter:
            self.easter = on
            if on:
                flog("EASTER EGG: 100 templates enrolled - fingerprint watermark unlocked")
            self._redraw_log(rebuild_bg=True)

    def set_result(self, text, good):
        flog(f"RESULT {text}")
        self.result.configure(text=text, fg="#9cff9c" if good else "#ffb4a8")

    def _on_view_resize(self):
        if self._last_u8 is not None and not getattr(self, "_resize_pending", False):
            self._resize_pending = True
            self.root.after(80, lambda: (setattr(self, "_resize_pending", False), self.show_image(self._last_u8)))

    def show_image(self, u8):
        from PIL import Image
        self._last_u8 = u8
        w, h = self.view.winfo_width(), self.view.winfo_height()
        scale = max(2, min((w - 4) / 64, (h - 4) / 60)) if w > 10 and h > 10 else 5
        im = Image.fromarray(u8).resize((int(64 * scale), int(60 * scale)), Image.BICUBIC)
        buf = io.BytesIO(); im.save(buf, "PNG")
        self.photo = tk.PhotoImage(data=base64.b64encode(buf.getvalue()).decode())
        self.view.configure(image=self.photo)

    # ---------- threading plumbing ----------
    def ui(self, fn, *a):
        self.q.put((fn, a))

    def _tick(self):
        try:
            while True:
                fn, a = self.q.get_nowait(); fn(*a)
        except queue.Empty:
            pass
        self.root.after(100, self._tick)

    def run_bg(self, fn, *a):
        if self.busy:
            self.logline("busy - wait for the current step to finish"); return
        self.busy = True; self.set_buttons()
        def wrap():
            try:
                fn(*a)
            except Exception as e:
                self.ui(self.set_state, "ERR", str(e)[:200]); self.ui(self.logline, f"ERROR: {e}")
            finally:
                self.busy = False; self.ui(self.set_buttons); self.ui(self.refresh_quick)
        threading.Thread(target=wrap, daemon=True).start()

    def set_buttons(self):
        inst = installed()
        st = self.fw.get("state")
        hw_ok = self.hw["ok"]
        if not hw_ok:
            st = "incompatible"
        ready = inst and st == "community"
        pkg = packaged_by()
        enabled = {"install": hw_ok and not pkg, "uninstall": inst and not pkg, "flash": inst and st in ("stock", "bootloader", "community-nopsk"),
                   "calib": ready, "enroll": ready, "more": ready, "delete": inst, "test": ready,
                   "options": True, "stop": self.busy}
        for k, b in self.buttons.items():
            b.configure(state=("normal" if enabled.get(k) and (not self.busy or k == "stop") else "disabled"))
        self.buttons["install"].configure(text=(f"Installed ({pkg})" if pkg else ("Update install" if inst else "Install")))
        n = self.prefs.get("presses", 5)
        self.buttons["enroll"].configure(text=f"Enroll ({n})")
        self.buttons["more"].configure(text=f"Add {n} more")

    # ---------- status ----------
    def refresh(self):
        self.hw = hardware.check()
        flog(f"hardware check: {hardware.summary(self.hw)}")
        self.refresh_quick()
        if not self.hw["ok"]:
            self.set_state("ERR", "This computer is not supported:\n" + "\n".join(self.hw["problems"]))
            self.status_vars["firmware"].set("not probed (hardware check failed)")
            return
        self.run_bg(self._probe)

    def refresh_quick(self):
        self.status_vars["hardware"].set(hardware.summary(self.hw))
        self.status_vars["system"].set(f"{os_pretty()} · user {self.user} · encryption "
                                       f"{('available (systemd credentials, TPM2)' if store.has_tpm2() else 'available (systemd credentials, host key)') if store.creds_supported() else 'NOT available (plaintext fallback)'}")
        plasma = subprocess.run(["plasmashell", "--version"], capture_output=True, text=True).stdout.strip() or "Plasma not found"
        self.status_vars["plasma"].set(f"{plasma} · service asus-fp: {service_state()}")
        pkg = packaged_by()
        self.status_vars["install"].set(("installed by " + pkg + " - update/remove it with " + pkg) if pkg and installed()
                                        else ("installed (lock-screen hook active)" if installed() else "not installed"))
        m = store.meta(self.user)
        d = daemon_cmd({"cmd": "status"})
        self.set_easter(bool(m and int(m.get("templates", 0)) >= 100))
        if m:
            self.status_vars["enroll"].set(f"{m.get('templates', '?')} templates stored ({m.get('note', '')})"
                                           + (f" · service has {d.get('enrolled')} loaded" if d and "enrolled" in d else " · service not reachable"))
            self.status_vars["protect"].set(m.get("protection", ""))
        else:
            self.status_vars["enroll"].set("none stored" + (" · calibrated (this session)" if d and d.get("has_session_calibration") else ""))
            self.status_vars["protect"].set("-")
        self.set_buttons()

    def _probe(self):
        if not installed():
            self.fw = {"state": "unknown", "firmware": "?"}
            self.ui(self.status_vars["firmware"].set, "unknown until installed (only the fingerprint service may access the sensor)")
            return
        self.ui(self.status_vars["firmware"].set, "asking the service…")
        r = None
        for _ in range(10):                       # the service restarts after saves/installs
            r = daemon_cmd({"cmd": "firmware"}, timeout=15)
            if r and "state" in r and r["state"] != "busy":
                break
            time.sleep(0.5)
        self.fw = r if r and "state" in r else {"state": "unknown", "firmware": "?"}
        txt = {"community": "community firmware - ready", "stock": "STOCK firmware - flash required (one-way)",
               "bootloader": "bootloader only - flash to finish", "community-nopsk": "community firmware without key - re-flash",
               "unknown": "unknown firmware - unsupported", "busy": "sensor busy - press Refresh",
               "error": f"sensor error: {self.fw.get('detail', '')}"}.get(self.fw["state"], self.fw["state"]) + f" ({self.fw.get('firmware', '?')})"
        if r is None:
            txt = "service not reachable (check: systemctl status asus-fp)"
        self.ui(self.status_vars["firmware"].set, txt)
        flog(f"status firmware: {txt} | service: {service_state()} | installed: {installed()} | daemon status: {daemon_cmd({'cmd': 'status'})}")

    # ---------- privileged actions ----------
    def pkexec(self, args, done=None):
        """Run the admin helper via pkexec (polkit password prompt), streaming output to the log."""
        wrapper = "asus-fp-install" if args[0] in ("install", "uninstall") else "asus-fp-admin"
        wpath = os.path.join(OPT, "bin", wrapper)
        if args[0] == "install" and os.environ.get("APPIMAGE"):
            args = ["install", self._staged_source()]   # root cannot read the AppImage's FUSE mount
        if os.path.exists(wpath):
            cmd = ["pkexec", wpath, *args]
        else:
            # first install (or repair of a broken install): run this source tree's installer
            src = args[1] if args[0] == "install" and os.environ.get("APPIMAGE") else (
                self._staged_source() if os.environ.get("APPIMAGE") else HERE)
            cmd = ["pkexec", "/usr/bin/python3", "-I", os.path.join(src, "run.py"), "admin", *args]
        def work():
            self.ui(self.logline, "$ " + " ".join(cmd[1:]))
            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            for line in p.stdout:
                self.ui(self.logline, line.rstrip())
            p.wait()
            self.ui(self.logline, f"[exit {p.returncode}]")
            if done:
                done(p.returncode)
        self.run_bg(work)

    def _staged_source(self):
        """Copy the AppImage payload to a private runtime dir root can read (FUSE mounts deny root)."""
        dst = os.path.join(RUN_DIR, "installer")
        if os.path.isdir(dst):
            shutil.rmtree(dst)
        os.makedirs(RUN_DIR, mode=0o700, exist_ok=True)
        shutil.copytree(HERE, dst, symlinks=False, ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "site-*"))
        for root, dirs, files in os.walk(dst):
            os.chmod(root, 0o755)
            for f in files:
                os.chmod(os.path.join(root, f), 0o644)
        return dst

    def install(self):
        self.hw = hardware.check()
        if not self.hw["ok"]:
            messagebox.showerror("Not supported", "This computer does not meet the requirements:\n\n- " + "\n- ".join(self.hw["problems"]))
            return
        if self.hw["warnings"] and not messagebox.askokcancel("Warnings", "Please read before installing:\n\n- " + "\n- ".join(self.hw["warnings"]) + "\n\nContinue?"):
            return
        if not messagebox.askokcancel("Install", "Install the fingerprint lock-screen hook system-wide?\n\n"
                                      "You will be asked for your password. Password unlock is never changed; "
                                      "this only adds a parallel fingerprint option to the KDE lock screen."):
            return
        self.pkexec(["install", HERE], done=lambda rc: self.ui(self.set_result, "INSTALLED" if rc == 0 else "INSTALL FAILED", rc == 0))

    def uninstall(self):
        if messagebox.askokcancel("Uninstall", "Remove the lock-screen hook and the installed files?\n(Stored enrollments are kept.)"):
            self.pkexec(["uninstall"], done=lambda rc: self.ui(self.set_result, "UNINSTALLED" if rc == 0 else "FAILED", rc == 0))

    def delete(self):
        if messagebox.askyesno("Delete enrollment", f"Delete the stored fingerprint enrollment for '{self.user}'?\nThe lock screen will fall back to password only."):
            self.pkexec(["delete", self.user], done=lambda rc: self.ui(self.set_result, "DELETED" if rc == 0 else "FAILED", rc == 0))

    PREFS_PATH = os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config"), "asus-fp", "gui.json")
    PRESS_CHOICES = (5, 10, 20, 50)

    def _load_prefs(self):
        try:
            p = json.load(open(self.PREFS_PATH))
            if p.get("presses") not in self.PRESS_CHOICES:
                p["presses"] = 5
            p.setdefault("logging", False)
            p.setdefault("dark", False)
            return p
        except (OSError, ValueError):
            return {"presses": 5, "logging": False, "dark": False}

    def _save_prefs(self):
        try:
            os.makedirs(os.path.dirname(self.PREFS_PATH), exist_ok=True)
            json.dump(self.prefs, open(self.PREFS_PATH, "w"))
        except OSError:
            pass

    def options(self):
        w = tk.Toplevel(self.root, bg=self.pal["bg"]); w.title("Options"); w.geometry("+140+120"); w.resizable(False, False)
        f = ttk.Frame(w, padding=16); f.pack(fill="both", expand=True)
        ttk.Label(f, text="Presses per Enroll / Add request:").grid(row=0, column=0, sticky="w")
        var = tk.StringVar(value=str(self.prefs.get("presses", 5)))
        cb = ttk.Combobox(f, textvariable=var, values=[str(x) for x in self.PRESS_CHOICES], width=6, state="readonly")
        cb.grid(row=0, column=1, sticky="w", padx=(8, 0))
        ttk.Label(f, text=f"More presses = more of the fingertip covered = more reliable matching.\n"
                          f"Up to {self.cfg['max_templates']} templates are kept in total (oldest dropped beyond that).",
                  style="Muted.TLabel").grid(row=1, column=0, columnspan=2, sticky="w", pady=(6, 12))

        def apply(*_):
            self.prefs["presses"] = int(var.get()); self._save_prefs(); self.set_buttons()
            flog(f"OPTIONS presses per request = {self.prefs['presses']}")
        cb.bind("<<ComboboxSelected>>", apply)
        logvar = tk.BooleanVar(value=bool(self.prefs.get("logging", False)))

        def toggle_log():
            if not logvar.get():
                flog("OPTIONS logging disabled")
            LOGGING["enabled"] = logvar.get()
            self.prefs["logging"] = logvar.get(); self._save_prefs()
            flog("OPTIONS logging enabled")
        ttk.Checkbutton(f, text="Enable logging (actions and match scores to the log folder; no images)",
                        variable=logvar, command=toggle_log).grid(row=2, column=0, columnspan=2, sticky="w", pady=(0, 6))
        darkvar = tk.BooleanVar(value=bool(self.prefs.get("dark", False)))

        def toggle_dark():
            self.prefs["dark"] = darkvar.get(); self._save_prefs()
            flog(f"OPTIONS dark mode {'on' if darkvar.get() else 'off'}")
            self.apply_theme()
            for win in (w,) + tuple(getattr(self, "_credit_wins", ())):
                try:
                    win.configure(bg=self.pal["bg"])
                except tk.TclError:
                    pass
        ttk.Checkbutton(f, text="Dark mode", variable=darkvar, command=toggle_dark).grid(row=3, column=0, columnspan=2, sticky="w", pady=(0, 6))
        ttk.Separator(f).grid(row=4, column=0, columnspan=2, sticky="ew", pady=6)
        ttk.Button(f, text="Credits", command=self.credits).grid(row=5, column=0, sticky="w")
        ttk.Button(f, text="Open log folder", command=lambda: (os.makedirs(LOG_DIR, exist_ok=True), subprocess.Popen(["xdg-open", LOG_DIR], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))).grid(row=5, column=1, sticky="e")
        ttk.Button(f, text="Close", command=w.destroy).grid(row=6, column=1, sticky="e", pady=(12, 0))

    def stop(self):
        self.stop_flag = True

    def credits(self):
        w = tk.Toplevel(self.root, bg=self.pal["bg"]); w.title("Credits"); w.geometry("+120+80")
        t = tk.Text(w, width=90, height=30, wrap="word", font=("Sans", 10), padx=12, pady=10,
                    bg=self.pal["field"], fg=self.pal["field_fg"], insertbackground=self.pal["field_fg"], highlightthickness=0)
        t.pack(fill="both", expand=True)
        path = os.path.join(HERE, "CREDITS.md")
        try:
            t.insert("end", open(path).read())
        except OSError:
            t.insert("end", "CREDITS.md not found")
        t.configure(state="disabled")
        ttk.Button(w, text="Close", command=w.destroy).pack(pady=6)

    # ---------- service operations (the service owns the sensor) ----------
    def _on_event(self, ev):
        if "state" in ev:
            self.ui(self.set_state, ev["state"], ev.get("msg", ""))
        elif "msg" in ev:
            self.ui(self.msg.configure, {"text": ev["msg"]})
        if "log" in ev:
            self.ui(self.logline, ev["log"])
        fr = ev.get("frame")
        if fr:
            import numpy as np
            finger = bool(fr.get("finger"))
            self.ui(self.flag.configure, {"text": f"is finger detected = {finger}", "fg": "#9cff9c" if finger else "#ffd0d0"})
            try:
                u8 = np.frombuffer(base64.b64decode(fr["preview"]), dtype=np.uint8).reshape(60, 64)
                self.ui(self.show_image, u8)
            except (ValueError, KeyError, TypeError):
                pass

    def _service_op(self, req, what):
        flog(f"{what.upper()} start: {req}")
        res = daemon_stream(req, self._on_event, stop_flag=lambda: self.stop_flag)
        flog(f"{what.upper()} end: {res}")
        return res or {"result": "error", "detail": "service closed the connection"}

    def calibrate(self):
        def work():
            res = self._service_op({"cmd": "calibrate"}, "calibrate")
            if res.get("result") == "calibrated":
                self.ui(self.set_result, "CALIBRATED", True)
            elif res.get("result") == "stopped":
                self.ui(self.set_state, "WAIT", "stopped")
            else:
                self.ui(self.set_state, "ERR", res.get("detail") or res.get("error", "calibration failed"))
        self.stop_flag = False
        self.run_bg(work)

    def enroll(self, append):
        def work():
            presses = int(self.prefs.get("presses", 5))
            res = self._service_op({"cmd": "enroll", "presses": presses, "append": append}, "enroll")
            if res.get("result") != "captured":
                if res.get("result") == "stopped":
                    self.ui(self.set_state, "WAIT", "stopped - nothing saved")
                else:
                    self.ui(self.set_state, "ERR", res.get("detail") or res.get("error", "enroll failed"))
                return
            self.ui(self.logline, f"{res.get('new')} new templates captured by the service")
            self.ui(self.set_state, "WAIT", f"{res.get('new')} presses captured - saving (password prompt)…")

            def after_save(rc):
                self.ui(self.set_state, "DONE" if rc == 0 else "ERR", "enrollment saved" if rc == 0 else "save failed")
                self.ui(self.set_result, "ENROLLED" if rc == 0 else "SAVE FAILED", rc == 0)
            self.busy = False                     # allow the pkexec step to run
            self.ui(self.pkexec, ["save", self.user] + (["--append"] if append else []), after_save)
        self.stop_flag = False
        self.run_bg(work)

    def test(self):
        def work():
            self.ui(self.set_result, "", True)
            res = self._service_op({"cmd": "test"}, "test")
            r = res.get("result")
            if r == "match":
                self.ui(self.set_state, "DONE", "fingerprint recognised")
                self.ui(self.set_result, "MATCH OK", True)
            elif r == "nomatch":
                self.ui(self.set_state, "DONE", "not recognised (details in: journalctl -u asus-fp)")
                self.ui(self.set_result, "NO MATCH", False)
            elif r == "stopped":
                self.ui(self.set_state, "WAIT", "stopped")
            else:
                self.ui(self.set_state, "ERR", res.get("detail") or res.get("error", "test failed"))
        self.stop_flag = False
        self.run_bg(work)

    # ---------- firmware flash ----------
    def flash(self):
        self.hw = hardware.check()
        if not hardware.find_sensor():
            messagebox.showerror("Not supported", "The Goodix 27c6:521d sensor was not found. Nothing will be flashed.")
            return
        FlashWarning(self)

    def do_flash(self, confirm_text):
        def work():
            self.ui(self.set_state, "WAIT", "downloading and verifying firmware…")
            path = firmware.download_firmware(os.path.join(RUN_DIR, "fw"), progress=lambda m: self.ui(self.logline, m))
            self.ui(self.set_state, "WAIT", "flashing (password prompt) - do NOT touch the sensor or close the app")

            def done(rc):
                try:
                    os.remove(path)
                except OSError:
                    pass
                self.ui(self.set_state, "DONE" if rc == 0 else "ERR", "flash complete" if rc == 0 else "flash failed - see the log")
                self.ui(self.set_result, "FLASHED" if rc == 0 else "FLASH FAILED", rc == 0)
                self.ui(self.refresh)
            self.busy = False
            self.ui(self.pkexec, ["flash", self.user, path, confirm_text], done)
        self.run_bg(work)

    def run(self):
        self.root.mainloop()


class FlashWarning:
    """Full-screen, modal warning. Exact confirmation text continues; anything else exits the program."""

    def __init__(self, app):
        self.app = app
        w = tk.Toplevel(app.root)
        self.w = w
        w.title("Firmware flash warning")
        w.attributes("-fullscreen", True)
        w.configure(bg="#5c0000")
        w.grab_set()
        w.protocol("WM_DELETE_WINDOW", self.abort)
        w.bind("<Escape>", lambda e: self.abort())
        f = tk.Frame(w, bg="#5c0000", padx=60, pady=40); f.pack(fill="both", expand=True)
        tk.Label(f, text="⚠  FIRMWARE FLASH WARNING  ⚠", font=("Sans", 30, "bold"), bg="#5c0000", fg="#ffd54f").pack(pady=(0, 24))
        tk.Label(f, text="This WILL permanently disable the fingerprint sensor for Windows.",
                 font=("Sans", 20, "bold"), bg="#5c0000", fg="#ffffff", wraplength=1100, justify="center").pack(pady=(0, 6))
        tk.Label(f, text="The original firmware cannot be restored, so Windows Hello fingerprint will never work on this "
                         "laptop again, even if you reinstall Windows.",
                 font=("Sans", 15), bg="#5c0000", fg="#ffffff", wraplength=1100, justify="center").pack(pady=(0, 22))
        bullets = ("•  The flash is ONE-WAY: the stock firmware cannot be backed up or re-installed.\n"
                   "•  The replacement is unofficial community firmware (goodix-fp-linux-dev), downloaded now and checked "
                   "against a known SHA-256.\n"
                   "•  If the flash fails part-way there is a small risk the sensor is left unusable.\n"
                   "•  Afterwards the sensor only works with this app on Linux.\n"
                   "•  The app stops before writing anything if the sensor's bootloader is not the expected one.")
        tk.Label(f, text=bullets, font=("Sans", 13), bg="#5c0000", fg="#ffe0e0", justify="left", wraplength=1100).pack(pady=(0, 18))
        links = tk.Frame(f, bg="#5c0000"); links.pack()
        ttk.Button(links, text="Open the manual flashing instructions", command=self.open_manual).pack(side="left", padx=6)
        ttk.Button(links, text="Open the community project page", command=lambda: webbrowser.open(firmware.MANUAL_URL)).pack(side="left", padx=6)
        tk.Label(f, text="Are you sure you want to do this?", font=("Sans", 20, "bold"), bg="#5c0000", fg="#ffffff").pack(pady=(30, 4))
        tk.Label(f, text=f"Type exactly:  {firmware.CONFIRM_TEXT}      (anything else closes the program)",
                 font=("Sans", 11), bg="#5c0000", fg="#ffd54f").pack(pady=(0, 8))
        self.entry = tk.Entry(f, font=("Sans", 16), width=28, justify="center"); self.entry.pack(); self.entry.focus_set()
        self.entry.bind("<Return>", lambda e: self.submit())
        tk.Button(f, text="Continue", font=("Sans", 13, "bold"), command=self.submit).pack(pady=14)

    def open_manual(self):
        local = os.path.join(HERE, "docs", "FLASHING.md")
        if os.path.exists(local):
            subprocess.Popen(["xdg-open", local], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            webbrowser.open(firmware.MANUAL_URL)

    def submit(self):
        text = self.entry.get()
        if text != firmware.CONFIRM_TEXT:
            self.abort()
            return
        self.w.grab_release(); self.w.destroy()
        self.app.do_flash(text)

    def abort(self):
        try:
            self.w.destroy(); self.app.root.destroy()
        finally:
            os._exit(0)


def main(argv=None):
    app = App()
    app.run()
    return 0
