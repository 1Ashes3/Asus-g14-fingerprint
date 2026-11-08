ASUS Fingerprint V1.2 — credits and acknowledgements
=====================================================

This app exists because other people reverse-engineered and documented the Goodix sensors first.

Goodix Fingerprint Linux Development community (https://github.com/goodix-fp-linux-dev)
  • goodix-fp-dump (MIT) — the USB protocol library and the 52xd device constants used here
    (vendored in third_party/goodix_fp_dump, see SOURCE.txt), the TLS-PSK capture flow, and the
    firmware/pairing-key flashing procedure this app's guarded flash is based on.
  • goodix-firmware — hosts the community firmware (Goodix property; downloaded at flash time, never
    bundled) at a pinned commit, verified by SHA-256.
  • libfprint fork (goodixtls driver for the 5110) and SIGFM — reference designs for the capture state
    machine and for matching on tiny sensors.
  • goodix-wireshark / goodix-ghidra — protocol documentation.

KDE / kscreenlocker — the Plasma 6 lock screen's parallel "kde-fingerprint" PAM service, which lets the
  fingerprint run alongside the password prompt without touching login.
Linux-PAM (pam_exec), systemd (systemd-creds credentials, LoadCredentialEncrypted, polkit integration),
  polkit/pkexec, udev.

Matching method: masked normalised cross-correlation after Padfield, "Masked object registration in the
  Fourier domain", IEEE Trans. Image Processing 21(5), 2012.

Python libraries: NumPy, OpenCV (opencv-python-headless), Pillow, PyUSB, Tk/Tkinter.

The sensor firmware (GFUSB_GM168SEC_APP_10019) and the sensor itself are products of Shenzhen Goodix
  Technology Co., Ltd. This project is not affiliated with Goodix, ASUS or KDE.

Built by 1Ashes3 with Claude (Anthropic), November 2026. Experiments, calibration and matcher evaluation were
  done on one ASUS ROG Zephyrus G14 GA401QM.
