"""Read-only compatibility check, run before anything touches the system (no root, no USB I/O).

Hard requirements (install, flash, calibrate and enroll are refused without them):
  - the Goodix fingerprint sensor 27c6:521d is present on USB
  - Linux with systemd and a KDE Plasma 6 lock screen (kscreenlocker "kde-fingerprint" PAM service)
Warnings (shown, but you may continue):
  - the machine is not an ASUS laptop (the app was built and tested on a ROG Zephyrus G14 GA401QM)
  - fprintd/pam_fprintd is installed (its lock-screen hook will be replaced by this app's)"""
import glob
import os
import platform
import re
import shutil
import subprocess

VID, PID = "27c6", "521d"
TESTED_MODELS = ("GA401QM", "GA401Q", "GA401")
VENDOR_PAM_PATHS = ["/etc/pam.d/kde-fingerprint", "/usr/lib/pam.d/kde-fingerprint", "/lib/pam.d/kde-fingerprint",
                    "/usr/lib64/pam.d/kde-fingerprint", "/usr/share/pam.d/kde-fingerprint"]


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return ""


def find_sensor():
    """Returns the sysfs path of the 27c6:521d device, or None."""
    for d in glob.glob("/sys/bus/usb/devices/*"):
        if _read(os.path.join(d, "idVendor")).lower() == VID and _read(os.path.join(d, "idProduct")).lower() == PID:
            return d
    return None


def other_goodix():
    """Other Goodix fingerprint sensors (different models this app does not support)."""
    out = []
    for d in glob.glob("/sys/bus/usb/devices/*"):
        if _read(os.path.join(d, "idVendor")).lower() == VID and _read(os.path.join(d, "idProduct")).lower() != PID:
            out.append(_read(os.path.join(d, "idProduct")))
    return out


GREETERS = ["/usr/lib/kscreenlocker_greet", "/usr/libexec/kscreenlocker_greet",
            "/usr/lib/x86_64-linux-gnu/libexec/kscreenlocker_greet", "/usr/lib64/libexec/kscreenlocker_greet"]


def plasma_major():
    """Works without a display (e.g. as root under pkexec): headless plasmashell --version, then
    the lock-screen greeter binary (Plasma 6's greeter knows the 'kde-fingerprint' service)."""
    exe = shutil.which("plasmashell") or ("/usr/bin/plasmashell" if os.path.exists("/usr/bin/plasmashell") else None)
    if exe and os.geteuid() != 0:              # never execute desktop binaries as root; root uses the greeter check
        try:
            env = {"PATH": "/usr/bin:/bin", "QT_QPA_PLATFORM": "offscreen", "HOME": "/tmp"}
            r = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=15, env=env)
            m = re.search(r"plasmashell\s+(\d+)\.\d+", r.stdout + r.stderr)
            if m:
                return int(m.group(1))
        except Exception:
            pass
    for g in GREETERS:
        if os.path.exists(g):
            try:
                with open(g, "rb") as f:
                    return 6 if b"kde-fingerprint" in f.read() else 5
            except OSError:
                pass
    return 0


def vendor_pam():
    for p in VENDOR_PAM_PATHS:
        if os.path.exists(p):
            return p
    return None


def check():
    """Returns dict(ok, problems[], warnings[], details{})."""
    problems, warnings = [], []
    sensor = find_sensor()
    vendor = _read("/sys/class/dmi/id/sys_vendor")
    product = _read("/sys/class/dmi/id/product_name")
    board = _read("/sys/class/dmi/id/board_name")
    plasma = plasma_major()
    pam = vendor_pam()
    details = {"sensor": "27c6:521d" if sensor else "not found", "vendor": vendor or "?", "product": product or "?",
               "board": board or "?", "plasma": plasma, "kernel": platform.release(), "vendor_pam": pam or "none"}

    if platform.system() != "Linux":
        problems.append("this app only runs on Linux")
    if not sensor:
        others = other_goodix()
        if others:
            problems.append(f"Goodix sensor 27c6:{others[0]} found, but only 27c6:521d is supported "
                            "(other models use different firmware and commands)")
        else:
            problems.append("no Goodix 27c6:521d fingerprint sensor found on this computer")
    if not os.path.isdir("/run/systemd/system"):
        problems.append("systemd is not running (the unlock service needs it)")
    if plasma < 6:
        problems.append(f"KDE Plasma 6 not detected (found {plasma or 'none'}); the lock-screen hook needs Plasma 6")
    if not pam:
        problems.append("the Plasma lock screen's 'kde-fingerprint' PAM service file was not found")

    if vendor and "ASUS" not in vendor.upper():
        warnings.append(f"this is not an ASUS laptop ({vendor} {product}); the app was built on a ROG Zephyrus G14 GA401QM")
    elif sensor and not any(m in (product + board).upper() for m in TESTED_MODELS):
        warnings.append(f"model {product or board} has not been tested (tested: ROG Zephyrus G14 GA401QM)")
    if os.path.exists("/usr/lib/security/pam_fprintd.so") or os.path.exists("/lib/security/pam_fprintd.so") or \
            glob.glob("/usr/lib*/security/pam_fprintd.so") or glob.glob("/lib/*/security/pam_fprintd.so"):
        warnings.append("fprintd is installed: its fingerprint line on the lock screen will be replaced by this app "
                        "(it cannot drive this sensor anyway)")
    return {"ok": not problems, "problems": problems, "warnings": warnings, "details": details}


def summary(res):
    d = res["details"]
    head = f"sensor {d['sensor']} · {d['vendor']} {d['product']} · Plasma {d['plasma'] or '?'}"
    if res["problems"]:
        return "NOT COMPATIBLE: " + "; ".join(res["problems"])
    if res["warnings"]:
        return f"compatible with warnings ({head}): " + "; ".join(res["warnings"])
    return f"compatible ({head})"
