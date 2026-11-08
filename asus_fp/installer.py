"""System installation (root). Called from admin.py: install <source-dir> | uninstall.

Layout: /opt/asus-fingerprint/{asus_fp,third_party,run.py,venv,bin}, /etc/asus-fp/config.json,
/etc/pam.d/kde-fingerprint (derived from the distro's vendor file), /etc/udev/rules.d/70-asus-fp.rules,
/usr/share/polkit-1/actions/org.asus-fp.policy, system unit asus-fp.service (user asus-fp),
/usr/share/applications/asus-fingerprint.desktop."""
import json
import os
import os.path
import re
import stat as _stat
import pwd
import shutil
import time
import subprocess
import sys

OPT = "/opt/asus-fingerprint"
ETC = "/etc/asus-fp"
PAM_FILE = "/etc/pam.d/kde-fingerprint"
PAM_BACKUP = "/etc/pam.d/kde-fingerprint.asus-fp.bak"
UDEV_FILE = "/etc/udev/rules.d/70-asus-fp.rules"
POLKIT_FILE = "/usr/share/polkit-1/actions/org.asus-fp.policy"
UNIT_FILE = "/etc/systemd/system/asus-fp.service"
SERVICE_USER = "asus-fp"
DESKTOP_FILE = "/usr/share/applications/asus-fingerprint.desktop"
MARK = "# managed by asus-fingerprint"
MIN_PYTHON = (3, 12)


def say(msg):
    print(msg, flush=True)


def run(cmd, check=False, **kw):
    say("  $ " + " ".join(cmd))
    return subprocess.run(cmd, check=check, **kw)


# ---------------- distro ----------------
def os_release():
    d = {}
    try:
        for line in open("/etc/os-release"):
            if "=" in line:
                k, v = line.rstrip().split("=", 1)
                d[k] = v.strip('"')
    except OSError:
        pass
    return d


def pkg_manager():
    for pm in ("pacman", "dnf", "apt-get", "zypper"):
        if shutil.which(pm):
            return pm
    return None


def ensure_system_packages():
    """python3 + venv + tk. Only installs what is missing."""
    pm = pkg_manager()
    need = []
    if subprocess.run([sys.executable, "-I", "-c", "import venv, ensurepip"], capture_output=True).returncode:
        need.append({"pacman": "python", "dnf": "python3", "apt-get": "python3-venv", "zypper": "python3"}.get(pm))
    if subprocess.run([sys.executable, "-I", "-c", "import tkinter"], capture_output=True).returncode:
        need.append({"pacman": "tk", "dnf": "python3-tkinter", "apt-get": "python3-tk", "zypper": "python3-tk"}.get(pm))
    need = [n for n in need if n]
    if not need:
        return
    say(f"installing system packages (via {pm}): {need}")
    if pm == "pacman":
        run(["pacman", "-S", "--noconfirm", "--needed", *need])
    elif pm == "dnf":
        run(["dnf", "install", "-y", *need])
    elif pm == "apt-get":
        run(["apt-get", "install", "-y", *need], env={**os.environ, "DEBIAN_FRONTEND": "noninteractive"})
    elif pm == "zypper":
        run(["zypper", "--non-interactive", "install", *need])


# ---------------- PAM ----------------
VENDOR_PAM_PATHS = ["/usr/lib/pam.d/kde-fingerprint", "/lib/pam.d/kde-fingerprint",
                    "/usr/lib64/pam.d/kde-fingerprint", "/usr/share/pam.d/kde-fingerprint"]
GENERIC_PAM = """#%PAM-1.0
auth       required                    pam_shells.so
auth       requisite                   pam_nologin.so
-auth      requisite                   pam_faillock.so      preauth
auth       required                    pam_exec.so          quiet stdout {pam_exe}
auth       optional                    pam_permit.so
auth       required                    pam_env.so

account    include                     {account_include}

password   required                    pam_deny.so

session    include                     {account_include}
"""


def derive_pam(pam_exe):
    """Take the distro's vendor kde-fingerprint stack and swap pam_fprintd for our pam_exec line."""
    base = None
    current = open(PAM_FILE).read() if os.path.exists(PAM_FILE) else ""
    if current and MARK not in current and "fp-pam-verify" not in current:
        base = PAM_FILE                                   # a local, non-ours file: use it as the base, keep a backup
        bak = PAM_BACKUP if not os.path.exists(PAM_BACKUP) else f"{PAM_BACKUP}.{time.strftime('%Y%m%d%H%M%S')}"
        shutil.copy2(PAM_FILE, bak)
        say(f"backed up existing {PAM_FILE} to {bak}")
    else:
        for p in VENDOR_PAM_PATHS:
            if os.path.exists(p):
                base = p; break
    ours = f"auth       required                    pam_exec.so          quiet stdout {pam_exe}\n"
    if base:
        out, replaced = [], 0
        with open(base) as fh:
            base_lines = fh.readlines()
        for line in base_lines:
            stripped = line.lstrip()
            replaceable = (not stripped.startswith("#")) and (
                "pam_fprintd.so" in line or "pam_exec.so" in line or "fp-pam-verify" in line)
            if replaceable:
                if replaced == 0:
                    out.append(ours)
                replaced += 1                      # drop any further verifier lines
            else:
                out.append(line)
        if replaced == 0:
            # no fprintd line: insert ours after the last preauth/nologin line, else at the top of auth
            idx = max([i for i, l in enumerate(out) if l.split()[:1] in (["auth"], ["-auth"]) and ("preauth" in l or "nologin" in l)] or [-1])
            out.insert(idx + 1, ours)
        text = "".join(out)
        src = base
    else:
        inc = "system-local-login" if os.path.exists("/etc/pam.d/system-local-login") else (
            "common-account" if os.path.exists("/etc/pam.d/common-account") else "system-auth")
        text = GENERIC_PAM.format(pam_exe=pam_exe, account_include=inc)
        src = "generic template"
    if not text.startswith("#%PAM-1.0"):
        text = "#%PAM-1.0\n" + text
    text = text.replace("#%PAM-1.0\n", f"#%PAM-1.0\n{MARK} (base: {src}); password unlock uses the 'kde' service and is untouched\n", 1)
    return text


def write_pam():
    """Atomic: write a temp file next to the target, then rename (a crash never leaves an empty stack)."""
    text = derive_pam(os.path.join(OPT, "bin", "asus-fp-pam"))
    tmp = PAM_FILE + ".asus-fp.tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(fd, "w") as f:
        f.write(text)
        f.flush(); os.fsync(f.fileno())
    os.chmod(tmp, 0o644)
    os.replace(tmp, PAM_FILE)
    say(f"PAM service written: {PAM_FILE}")


def check_source_tree(src, owner_uid):
    """Every directory/file in the source must be owned by root or the invoking user and not writable by
    group/others, so no third party can swap code that root is about to install."""
    for root, dirs, files in os.walk(src):
        dirs[:] = [d for d in dirs if d not in ("__pycache__", "logs", ".venv")]
        for path in [root] + [os.path.join(root, f) for f in files]:
            st = os.lstat(path)
            if _stat.S_ISLNK(st.st_mode):
                raise SystemExit(f"refusing symlink in source: {path}")
            if st.st_uid not in (0, owner_uid) or st.st_mode & 0o022:
                raise SystemExit(f"refusing source path with unsafe owner/permissions: {path}")


def _copy_regular(sp, dp):
    fd = os.open(sp, os.O_RDONLY | os.O_NOFOLLOW | os.O_NOCTTY)
    try:
        st = os.fstat(fd)
        if not _stat.S_ISREG(st.st_mode):
            raise SystemExit(f"refusing non-regular file in source: {sp}")
        with os.fdopen(fd, "rb") as fin:
            fd = None
            data = fin.read()
    finally:
        if fd is not None:
            os.close(fd)
    out = os.open(dp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
    with os.fdopen(out, "wb") as fout:
        fout.write(data)
    os.chmod(dp, 0o644)


def safe_copytree(src, dst):
    """Copy only regular files and directories, reading each file through an O_NOFOLLOW descriptor."""
    for root, dirs, files in os.walk(src):
        rel = os.path.relpath(root, src)
        if os.path.islink(root):
            raise SystemExit(f"refusing symlinked directory in source: {root}")
        dirs[:] = [d for d in dirs if d != "__pycache__"]
        target = os.path.join(dst, rel) if rel != "." else dst
        os.makedirs(target, mode=0o755, exist_ok=True)
        for f in files:
            if f.endswith(".pyc"):
                continue
            _copy_regular(os.path.join(root, f), os.path.join(target, f))


# ---------------- install ----------------
def install(source):
    if os.path.exists(os.path.join(OPT, ".packaged")):
        raise SystemExit("this installation is managed by the package manager - update or remove it there")
    source = os.path.realpath(source)
    for sub in ("asus_fp", "third_party", "run.py", "packaging"):
        if not os.path.exists(os.path.join(source, sub)):
            raise SystemExit(f"source dir {source} is missing {sub}")
    updating_in_place = (source == os.path.realpath(OPT))
    if sys.version_info[:2] < MIN_PYTHON:
        raise SystemExit(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ is required (found {sys.version.split()[0]})")
    if not updating_in_place:
        invoker = int(os.environ.get("PKEXEC_UID") or os.environ.get("SUDO_UID") or "0")
        check_source_tree(source, invoker)
    osr = os_release()
    say(f"distro: {osr.get('PRETTY_NAME', '?')}; package manager: {pkg_manager()}")
    import importlib.util
    spec = importlib.util.spec_from_file_location("asus_fp_hw_src", os.path.join(source, "asus_fp", "hardware.py"))
    hardware = importlib.util.module_from_spec(spec); spec.loader.exec_module(hardware)
    hw = hardware.check()
    say("hardware check: " + hardware.summary(hw))
    for w in hw["warnings"]:
        say(f"warning: {w}")
    if not hw["ok"]:
        say("NOT INSTALLING - this computer does not meet the requirements:\n  - " + "\n  - ".join(hw["problems"]))
        raise SystemExit(1)
    ensure_system_packages()

    # code
    os.makedirs(OPT, mode=0o755, exist_ok=True)
    if updating_in_place:
        say("source is the installed tree: keeping code, refreshing system files only")
    else:
        for sub in ("asus_fp", "third_party", "packaging"):
            dst = os.path.join(OPT, sub)
            if os.path.isdir(dst):
                shutil.rmtree(dst)
            safe_copytree(os.path.join(source, sub), dst)
        for f in ("run.py", "README.md", "CREDITS.md"):
            if os.path.exists(os.path.join(source, f)):
                _copy_regular(os.path.join(source, f), os.path.join(OPT, f))
        if os.path.isdir(os.path.join(source, "docs")):
            if os.path.isdir(os.path.join(OPT, "docs")):
                shutil.rmtree(os.path.join(OPT, "docs"))
            safe_copytree(os.path.join(source, "docs"), os.path.join(OPT, "docs"))
        say(f"code installed to {OPT}")

    # venv
    venv_py = os.path.join(OPT, "venv", "bin", "python")
    if not os.path.exists(venv_py):
        say("creating Python environment (downloads numpy/opencv/pillow/pyusb)...")
        run([sys.executable, "-m", "venv", os.path.join(OPT, "venv")], check=True)
    req = os.path.join(OPT, "packaging", "requirements.txt")
    wheels = os.path.join(source, "wheels")
    r = run([venv_py, "-I", "-c", "import numpy, cv2, PIL, usb"], capture_output=True)
    if r.returncode:
        extra = ["--no-index", "--find-links", wheels] if os.path.isdir(wheels) else []   # AppImage: offline
        run([os.path.join(OPT, "venv", "bin", "pip"), "install", "-q", "--no-cache-dir", "--only-binary=:all:",
             "--require-hashes", *extra, "-r", req], check=True)
    say("python environment ready")

    # wrappers
    bindir = os.path.join(OPT, "bin")
    os.makedirs(bindir, exist_ok=True)
    wrappers = {
        "asus-fp-admin": f'#!/bin/sh\nexec "{venv_py}" -I "{OPT}/run.py" admin --role=admin "$@"\n',
        "asus-fp-install": f'#!/bin/sh\nexec "{venv_py}" -I "{OPT}/run.py" admin --role=install "$@"\n',
        "asus-fp-daemon": f'#!/bin/sh\nexec "{venv_py}" -I "{OPT}/run.py" daemon "$@"\n',
        "asus-fp-pam": f'#!/bin/sh\nexport PATH=/usr/local/bin:/usr/bin:/bin\nunset PYTHONPATH PYTHONHOME LD_PRELOAD LD_LIBRARY_PATH\nexec /usr/bin/python3 -I -E -s "{OPT}/run.py" pam\n',
        "asus-fingerprint": f'#!/bin/sh\nexec "{venv_py}" -I "{OPT}/run.py" gui "$@"\n',
    }
    for name, body in wrappers.items():
        p = os.path.join(bindir, name)
        with open(p, "w") as f:
            f.write(body)
        os.chmod(p, 0o755)

    # config
    os.makedirs(ETC, exist_ok=True)
    cfgp = os.path.join(ETC, "config.json")
    if not os.path.exists(cfgp):
        sys.path.insert(0, OPT)
        from asus_fp import config as cfgmod
        with open(cfgp, "w") as f:
            json.dump(cfgmod.DEFAULTS, f, indent=1)
    os.chmod(cfgp, 0o644)

    # udev / polkit / unit / desktop from packaging templates
    pk = os.path.join(OPT, "packaging")
    subst = lambda s: s.replace("@OPT@", OPT)
    for src, dst, mode in (("70-asus-fp.rules", UDEV_FILE, 0o644), ("org.asus-fp.policy", POLKIT_FILE, 0o644),
                           ("asus-fp.service", UNIT_FILE, 0o644), ("asus-fingerprint.desktop", DESKTOP_FILE, 0o644)):
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(os.path.join(pk, src)) as f:
            body = subst(f.read())
        with open(dst, "w") as f:
            f.write(body)
        os.chmod(dst, mode)
    if subprocess.run(["id", SERVICE_USER], capture_output=True).returncode:
        run(["useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin" if os.path.exists("/usr/sbin/nologin") else "/usr/bin/nologin",
             "--home-dir", "/var/lib/asus-fp", SERVICE_USER], check=True)
    os.makedirs("/var/lib/asus-fp", mode=0o755, exist_ok=True)
    sys.path.insert(0, OPT)
    from asus_fp import store as _store
    _store.write_dropin()
    run(["udevadm", "control", "--reload"]); run(["udevadm", "trigger", "--subsystem-match=usb", "--attr-match=idVendor=27c6"])
    run(["systemctl", "daemon-reload"]); run(["systemctl", "enable", "asus-fp.service"])

    # PAM
    write_pam()

    run(["systemctl", "restart", "asus-fp.service"], check=False)
    say("INSTALL COMPLETE")


def package_hook(stage):
    """Called by distro package scripts (root). post-install/post-upgrade: PAM file, enrollment drop-in,
    enable+start the service. pre-remove: stop the service, remove our PAM file (restoring a backup)."""
    sys.path.insert(0, OPT)
    from asus_fp import store as _store
    if stage in ("post-install", "post-upgrade"):
        os.makedirs("/var/lib/asus-fp", mode=0o755, exist_ok=True)
        _store.write_dropin()
        write_pam()
        run(["systemctl", "daemon-reload"], check=False)
        run(["systemctl", "enable", "asus-fp.service"], check=False)
        run(["systemctl", "restart", "asus-fp.service"], check=False)
    elif stage == "pre-remove":
        run(["systemctl", "disable", "--now", "asus-fp.service"], check=False)
        if os.path.isdir("/etc/systemd/system/asus-fp.service.d"):
            shutil.rmtree("/etc/systemd/system/asus-fp.service.d")
        if os.path.exists(PAM_FILE) and MARK in open(PAM_FILE).read():
            os.remove(PAM_FILE)
            if os.path.exists(PAM_BACKUP) and "fp-pam-verify" not in open(PAM_BACKUP).read():
                shutil.move(PAM_BACKUP, PAM_FILE)
        say("fingerprint unlock removed (enrollments kept in /var/lib/asus-fp)")
    else:
        raise SystemExit(f"unknown hook stage {stage}")


def uninstall():
    run(["systemctl", "disable", "--now", "asus-fp.service"], check=False, capture_output=True)
    if os.path.isdir("/etc/systemd/system/asus-fp.service.d"):
        shutil.rmtree("/etc/systemd/system/asus-fp.service.d")
    if os.path.exists(PAM_FILE) and MARK in open(PAM_FILE).read():
        os.remove(PAM_FILE)
        if os.path.exists(PAM_BACKUP) and "fp-pam-verify" not in open(PAM_BACKUP).read():
            shutil.move(PAM_BACKUP, PAM_FILE)
            say("restored previous kde-fingerprint PAM file")
    for p in (UDEV_FILE, POLKIT_FILE, UNIT_FILE, DESKTOP_FILE):
        if os.path.exists(p):
            os.remove(p)
    run(["udevadm", "control", "--reload"], check=False); run(["systemctl", "daemon-reload"], check=False)
    if os.path.isdir(OPT):
        shutil.rmtree(OPT)
    if os.path.isdir(ETC):
        shutil.rmtree(ETC)
    say("UNINSTALL COMPLETE (enrollments in /var/lib/asus-fp were kept; delete them from the app or by hand)")
