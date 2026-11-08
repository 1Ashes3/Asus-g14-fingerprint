#!/usr/bin/python3
"""PAM side (pam_exec, service kde-fingerprint). Standard library only, starts in ~50 ms.

Connects to the asus-fp system service on /run/asus-fp/sock, checks (SO_PEERCRED) that the peer really
is the `asus-fp` service user (so no user-level process can impersonate it), relays its messages to
the lock screen (pam_exec 'stdout'), and exits 0 only on a confirmed match. Dies with the PAM worker
(PR_SET_PDEATHSIG), which closes the socket and makes the service abort the verify."""
import ctypes
import json
import os
import pwd
import socket
import struct
import sys
import time

SOCK = "/run/asus-fp/sock"
SERVICE_USER = "asus-fp"
MAX_TIMEOUT = 180.0


def _timeout():
    try:
        t = float(os.environ.get("PAM_TIMEOUT", MAX_TIMEOUT))
    except ValueError:
        return MAX_TIMEOUT
    return t if 1.0 <= t <= MAX_TIMEOUT else MAX_TIMEOUT


TIMEOUT = _timeout()


def say(msg):
    try:
        sys.stdout.write(msg + "\n"); sys.stdout.flush()
    except Exception:
        pass


def main():
    parent = os.getppid()
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl(1, 15, 0, 0, 0)                  # PR_SET_PDEATHSIG, SIGTERM
    except Exception:
        pass
    if os.getppid() != parent:
        return 1
    user = os.environ.get("PAM_USER", "")
    try:
        if not user or pwd.getpwnam(user).pw_uid != os.getuid():
            return 1                                # only verify the user we are running as
        service_uid = pwd.getpwnam(SERVICE_USER).pw_uid
    except KeyError:
        return 1
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(3)
    try:
        s.connect(SOCK)
        creds = s.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _pid, peer_uid, _gid = struct.unpack("3i", creds)
        if peer_uid != service_uid:
            return 1                                # not the real service
    except OSError:
        time.sleep(0.4)                             # service not running: quiet failure, password still works
        return 1
    try:
        s.sendall((json.dumps({"cmd": "verify", "user": user, "timeout": TIMEOUT}) + "\n").encode())
        s.settimeout(TIMEOUT + 10)
        buf = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                return 1
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                try:
                    obj = json.loads(line.decode())
                except ValueError:
                    continue
                if "msg" in obj:
                    say(obj["msg"])
                if "result" in obj:
                    return 0 if obj["result"] == "match" else 1
                if "error" in obj:
                    return 1
    except OSError:
        return 1
    finally:
        s.close()


if __name__ == "__main__":
    sys.exit(main())
