#!/usr/bin/env python3
"""Entry point: run.py gui | daemon | pam | admin <args>  (works from the source tree or /opt)."""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


def main():
    cmd = sys.argv[1] if len(sys.argv) > 1 else "gui"
    rest = sys.argv[2:]
    if cmd == "pam":
        from asus_fp import pam_client
        return pam_client.main()
    if cmd == "daemon":
        from asus_fp import daemon
        return daemon.main()
    if cmd == "admin":
        from asus_fp import admin
        return admin.main(["admin"] + rest)
    if cmd == "gui":
        from asus_fp import gui
        return gui.main(rest)
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main() or 0)
