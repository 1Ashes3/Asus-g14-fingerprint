"""Privileged helper, run as root through pkexec (polkit action org.asus-fp.admin).

  admin.py save <user> [--append]       store (or merge into) the enrollment the SERVICE captured
                                        (read from /run/asus-fp/pending-<user>.npz, owned by asus-fp)
  admin.py delete <user>                remove the stored enrollment
  admin.py flash <user> <firmware.bin> <confirmation text>   guarded one-way firmware flash
  admin.py install <source-dir>         install/upgrade system files
  admin.py uninstall                              remove the system files (keeps /var/lib/asus-fp)

The acting user is taken from PKEXEC_UID (or the real uid when run by root directly); <user> must
match it, so a user can only touch their own enrollment. Never trusts paths from the environment."""
import json
import os
import pwd
import shutil
import stat
import subprocess
import sys

from . import store

OPT = "/opt/asus-fingerprint"
ETC = "/etc/asus-fp"
RUN_DIR = "/run/asus-fp"
SERVICE_USER = "asus-fp"


def fail(msg, code=1):
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(code)


def acting_user():
    uid = os.environ.get("PKEXEC_UID")
    if uid is None:
        uid = os.getuid() if os.getuid() != 0 else None
    if uid is None:
        return None, None
    pw = pwd.getpwuid(int(uid))
    return pw.pw_name, pw.pw_uid


def require_user(arg):
    if not store.valid_user(arg):
        fail("invalid user name")
    name, uid = acting_user()
    if name is None:
        if os.getuid() == 0:
            return arg, pwd.getpwnam(arg).pw_uid          # root at a terminal may act for any user
        fail("cannot determine the acting user")
    if arg != name:
        fail(f"user '{arg}' is not the user who invoked this action ({name})")
    return name, uid


def restart_service():
    subprocess.run(["systemctl", "daemon-reload"], check=False)
    r = subprocess.run(["systemctl", "restart", "asus-fp.service"], capture_output=True, text=True)
    if r.returncode:
        print(f"warning: service restart failed: {r.stderr.strip()}")


def read_pending(user):
    """The service writes /run/asus-fp/pending-<user>.npz (0600, owner asus-fp, dir owned by asus-fp)."""
    import numpy as np
    path = os.path.join(RUN_DIR, f"pending-{user}.npz")
    try:
        svc_uid = pwd.getpwnam(SERVICE_USER).pw_uid
        dst = os.lstat(RUN_DIR)
        if not stat.S_ISDIR(dst.st_mode) or dst.st_uid != svc_uid or dst.st_mode & 0o022:
            fail("service runtime directory has unexpected ownership/permissions")
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    except (OSError, KeyError) as e:
        fail(f"no captured enrollment waiting (run Enroll first): {e}")
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != svc_uid or st.st_mode & 0o077 or st.st_size > 64 * 1024 * 1024:
            fail("pending file has unexpected owner, mode or size")
        with os.fdopen(fd, "rb") as f:
            z = np.load(f, allow_pickle=False)
            arrays = {k: z[k] for k in z.files}
    except (OSError, ValueError) as e:
        fail(f"cannot read pending file: {e}")
    for key in ("templates", "bg", "noise", "gain", "dac", "variant"):
        if key not in arrays:
            fail(f"pending enrollment is missing '{key}'")
    t = arrays["templates"]
    if t.ndim != 3 or t.shape[1:] != (60, 64) or not (1 <= t.shape[0] <= 100):
        fail("pending enrollment has an unexpected template shape")
    if arrays["bg"].shape != (60, 64):
        fail("pending enrollment has no calibration background")
    for key in ("noise", "gain"):
        if arrays[key].shape not in ((0,), (60, 64)):
            fail(f"pending enrollment '{key}' has an unexpected shape")
    for key in ("templates", "bg", "noise", "gain"):
        if arrays[key].dtype.kind != "f" or arrays[key].nbytes > 16 * 1024 * 1024 or not np.isfinite(arrays[key]).all():
            fail(f"pending enrollment '{key}' has an unexpected dtype, size or non-finite values")
    if not (0x80 <= int(arrays["dac"]) <= 0x1FF):
        fail("pending enrollment has an out-of-range DAC")
    if str(arrays["variant"]) not in ("clahe", "dog"):
        fail("pending enrollment has an unknown preprocessing variant")
    return arrays


def remove_pending(user):
    try:
        os.remove(os.path.join(RUN_DIR, f"pending-{user}.npz"))
    except OSError:
        pass


def merge(existing, new, max_templates=100):
    import numpy as np
    sys.path.insert(0, OPT if os.path.isdir(os.path.join(OPT, "asus_fp")) else os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from asus_fp import matcher
    t = list(existing["templates"]) + list(new["templates"])
    t = t[-max_templates:]
    gain = matcher.build_gain_map(t, 12)
    return {"templates": np.stack(t).astype(np.float32), "bg": new["bg"], "noise": new["noise"],
            "gain": gain if gain is not None else np.zeros((0,), np.float32),
            "dac": new["dac"], "variant": new["variant"]}


def cmd_save(user, append):
    user, uid = require_user(user)
    arrays = read_pending(user)
    remove_pending(user)
    if append:
        old = store.load_arrays_root(user)
        if old is not None:
            arrays = merge({k: old[k] for k in old.files}, arrays)
    m = store.save(user, arrays, note="enrolled via app" + (" (appended)" if append else ""))
    restart_service()
    print(json.dumps(m))


def cmd_delete(user):
    user, _ = require_user(user)
    found = store.delete(user)
    restart_service()
    print(json.dumps({"deleted": found, "user": user}))


def cmd_flash(user, fw_path, confirm):
    """Root flash: the firmware file must be a regular user-owned file in the user's runtime dir; its SHA-256
    and the confirmation text are re-checked by firmware.flash(). The service is stopped meanwhile."""
    user, uid = require_user(user)
    allowed = os.path.realpath(f"/run/user/{uid}")
    rp = os.path.realpath(fw_path)
    if not rp.startswith(allowed + os.sep):
        fail("firmware file must be under the user's runtime directory")
    fd = os.open(rp, os.O_RDONLY | os.O_NOFOLLOW)
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != uid or st.st_size > 1024 * 1024:
        fail("firmware file is not a regular user-owned file of plausible size")
    with os.fdopen(fd, "rb") as f:
        data = f.read()
    tmp = "/run/asus-fp-firmware.bin"
    fd2 = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd2, "wb") as f:
        f.write(data)
    from . import firmware, hardware
    if not hardware.find_sensor():
        fail("Goodix 27c6:521d sensor not present")
    subprocess.run(["systemctl", "stop", "asus-fp.service"], check=False)
    try:
        res = firmware.flash(tmp, confirm, progress=lambda m: print(m, flush=True))
        print(json.dumps(res))
    finally:
        os.remove(tmp)
        subprocess.run(["systemctl", "start", "asus-fp.service"], check=False)


def main(argv):
    if os.getuid() != 0:
        fail("must run as root (via pkexec)")
    os.umask(0o022)
    if len(argv) < 2:
        print(__doc__); return 2
    flags = [a for a in argv[1:] if a.startswith("--")]
    pos = [a for a in argv[1:] if not a.startswith("--")]
    if not pos:
        print(__doc__); return 2
    cmd, args = pos[0], pos[1:]
    role = next((f.split("=", 1)[1] for f in flags if f.startswith("--role=")), "any")
    if role == "admin" and cmd in ("install", "uninstall"):
        fail("install/uninstall must go through asus-fp-install (separate polkit action)")
    if role == "admin" and cmd == "package-hook":
        fail("package hooks must go through asus-fp-install")
    if role == "install" and cmd not in ("install", "uninstall", "package-hook"):
        fail("asus-fp-install only installs or uninstalls")
    if cmd == "save" and len(args) == 1:
        cmd_save(args[0], "--append" in flags)
    elif cmd == "flash" and len(args) == 3:
        cmd_flash(*args)
    elif cmd == "delete" and len(args) == 1:
        cmd_delete(*args)
    elif cmd == "install" and len(args) == 1:
        from . import installer
        installer.install(args[0])
    elif cmd == "package-hook" and len(args) == 1:
        from . import installer
        installer.package_hook(args[0])
    elif cmd == "uninstall" and not args:
        from . import installer
        installer.uninstall()
    else:
        print(__doc__); return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
