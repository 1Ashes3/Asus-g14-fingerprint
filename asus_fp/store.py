"""Enrollment store: /var/lib/asus-fp/<user>.cred, root-owned 0600, written only by admin.py (root).

Encryption: systemd *system-scoped* credentials (`systemd-creds encrypt --with-key=auto`): sealed to
the TPM2 when present, plus the machine's root-only host secret. The blob is never decrypted by a user
process: systemd decrypts it for the asus-fp service (LoadCredentialEncrypted=) into the service's
private credentials directory, and admin.py (root) decrypts it only to merge new templates.
Fallback when systemd-creds is unavailable: root-owned plaintext .npz (reported as such)."""
import io
import json
import os
import re
import shutil
import subprocess

VAR_DIR = "/var/lib/asus-fp"
DROPIN_DIR = "/etc/systemd/system/asus-fp.service.d"
DROPIN = os.path.join(DROPIN_DIR, "10-enrollments.conf")
NAME_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}$")


def valid_user(name):
    return bool(name) and bool(NAME_RE.match(name))


def cred_name(user):
    return f"enroll-{user}"


def cred_path(user):
    if not valid_user(user):
        raise ValueError("invalid user name")
    return os.path.join(VAR_DIR, f"{user}.cred")


def plain_path(user):
    if not valid_user(user):
        raise ValueError("invalid user name")
    return os.path.join(VAR_DIR, f"{user}.npz")


def meta_path(user):
    if not valid_user(user):
        raise ValueError("invalid user name")
    return os.path.join(VAR_DIR, f"{user}.json")


def creds_supported():
    if not shutil.which("systemd-creds"):
        return False
    try:
        v = subprocess.run(["systemd-creds", "--version"], capture_output=True, text=True, timeout=5).stdout
        return int(re.search(r"systemd (\d+)", v).group(1)) >= 250
    except Exception:
        return False


def has_tpm2():
    r = subprocess.run(["systemd-analyze", "has-tpm2"], capture_output=True, text=True)
    return r.returncode == 0 and r.stdout.strip().startswith("yes")


def encrypt_system(data: bytes, name: str) -> bytes:
    """Root: system-scoped credential, key = TPM2 + host secret when available ("auto")."""
    r = subprocess.run(["systemd-creds", "encrypt", "--with-key=auto", f"--name={name}", "-", "-"],
                       input=data, capture_output=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"systemd-creds encrypt failed: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


def decrypt_system(blob: bytes, name: str) -> bytes:
    """Root only (admin merge). The service never calls this; systemd decrypts for it."""
    r = subprocess.run(["systemd-creds", "decrypt", f"--name={name}", "-", "-"],
                       input=blob, capture_output=True, timeout=120)
    if r.returncode != 0:
        raise RuntimeError(f"systemd-creds decrypt failed: {r.stderr.decode(errors='replace').strip()}")
    return r.stdout


CRED_MAX = 1024 * 1024 - 64 * 1024          # systemd-creds plaintext limit is 1 MiB; keep headroom


def npz_bytes(arrays: dict) -> bytes:
    import numpy as np
    buf = io.BytesIO()
    np.savez(buf, **arrays)
    return buf.getvalue()


def compact_bytes(arrays: dict) -> bytes:
    """Storage form: templates as int16 (12-bit sensor data, rounding < 0.5 count), compressed npz.
    Drops the oldest templates if the blob would exceed the credential size limit."""
    import numpy as np
    a = dict(arrays)
    t = np.clip(np.rint(np.asarray(a["templates"], np.float32)), -32768, 32767).astype(np.int16)
    while True:
        a["templates"] = t
        buf = io.BytesIO()
        np.savez_compressed(buf, **a)
        data = buf.getvalue()
        if len(data) <= CRED_MAX or t.shape[0] <= 1:
            return data
        t = t[1:]                                  # oldest first


def load_npz(data: bytes):
    import numpy as np
    return np.load(io.BytesIO(data), allow_pickle=False)


def _write_private(path, data):
    tmp = path + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def save(user, arrays: dict, note=""):
    """Root only. Writes the enrollment blob + meta and refreshes the service drop-in. Returns meta."""
    os.makedirs(VAR_DIR, mode=0o755, exist_ok=True)
    data = compact_bytes(arrays)
    stored = load_npz(data)
    arrays = dict(arrays); arrays["templates"] = stored["templates"]
    encrypted = creds_supported()
    if encrypted:
        _write_private(cred_path(user), encrypt_system(data, cred_name(user)))
        if os.path.exists(plain_path(user)):
            os.remove(plain_path(user))
        protection = "systemd credential: " + ("TPM2-sealed + host key" if has_tpm2() else "host key (no TPM2)") + \
                     ", decrypted only by systemd for the asus-fp service"
    else:
        _write_private(plain_path(user), data)
        if os.path.exists(cred_path(user)):
            os.remove(cred_path(user))
        protection = "root-owned plaintext (systemd-creds unavailable)"
    meta = {"user": user, "encrypted": encrypted, "protection": protection,
            "templates": int(arrays["templates"].shape[0]), "dac": int(arrays["dac"]), "note": note}
    with open(meta_path(user), "w") as f:
        json.dump(meta, f, indent=1)
    os.chmod(meta_path(user), 0o644)
    write_dropin()
    return meta


def load_arrays_root(user):
    """Root only: current stored enrollment arrays (for merging), or None."""
    if os.path.exists(cred_path(user)):
        with open(cred_path(user), "rb") as f:
            return load_npz(decrypt_system(f.read(), cred_name(user)))
    if os.path.exists(plain_path(user)):
        with open(plain_path(user), "rb") as f:
            return load_npz(f.read())
    return None


def delete(user):
    """Root only."""
    found = False
    for p in (cred_path(user), plain_path(user), meta_path(user)):
        if os.path.exists(p):
            os.remove(p); found = True
    write_dropin()
    return found


def enrolled_users():
    users = []
    if os.path.isdir(VAR_DIR):
        for f in os.listdir(VAR_DIR):
            if f.endswith(".cred") or f.endswith(".npz"):
                u = f.rsplit(".", 1)[0]
                if valid_user(u) and u not in users:
                    users.append(u)
    return sorted(users)


def meta(user):
    try:
        with open(meta_path(user)) as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def write_dropin():
    """Root only: one LoadCredentialEncrypted= (or LoadCredential= for plaintext) per enrolled user.
    The service must be restarted afterwards (admin.py does that)."""
    os.makedirs(DROPIN_DIR, mode=0o755, exist_ok=True)
    lines = ["[Service]"]
    for u in enrolled_users():
        if os.path.exists(cred_path(u)):
            lines.append(f"LoadCredentialEncrypted={cred_name(u)}:{cred_path(u)}")
        else:
            lines.append(f"LoadCredential={cred_name(u)}:{plain_path(u)}")
    with open(DROPIN, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(DROPIN, 0o644)
