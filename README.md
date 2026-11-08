# ASUS Fingerprint (Goodix 27c6:521d) – lock-screen unlock for Linux, V1.2

Fingerprint unlock for the **KDE Plasma 6 lock screen** on laptops with the Goodix `27c6:521d` sensor
(ASUS ROG Zephyrus G14 GA401QM and similar). It does **not** touch login, `sudo` or polkit: the password
always keeps working, the fingerprint is an extra option on the lock screen only.

Built on the open-source protocol work of [goodix-fp-linux-dev](https://github.com/goodix-fp-linux-dev)
(MIT). No vendor code is used. Matching is a dense masked-correlation matcher designed for this tiny
(64×60 px, ~3 mm) sensor.

Developed with the help of Claude (Anthropic); tested on the author's own ASUS ROG Zephyrus G14 GA401QM.

## Requirements

- KDE Plasma **6** (uses kscreenlocker's parallel `kde-fingerprint` PAM service).
- Arch-based (CachyOS, EndeavourOS, Manjaro…), Fedora, or Debian/Ubuntu. Other distros may work.
- Python 3.12+ with tkinter (the launcher offers to install your distro's Tk package if it is missing), systemd ≥ 250 (credentials); a TPM 2.0 for sealed storage (otherwise host-key
  encryption; without `systemd-creds` at all a root-only plaintext store, and the app says so).
- Internet access once, for the Python packages (numpy, OpenCV, Pillow, pyusb) and, if your sensor is
  still on stock firmware, the community firmware download.

## Safety check before anything is changed

On start (and again before Install and before any flash) the app runs a read-only compatibility check.
It refuses to install, flash, calibrate or enroll unless the Goodix **27c6:521d** sensor is present
(other Goodix models are detected and refused), systemd is running, and a KDE **Plasma 6** lock screen
with its `kde-fingerprint` PAM service exists. Non-ASUS or untested models and an installed fprintd
produce warnings you must acknowledge. The installer repeats the check as root.

## Install and use

```sh
./asus-fingerprint          # from this folder; or double-click "ASUS Fingerprint" after installing
```

In the app (top to bottom, first time):

1. **Install** – asks for your password (polkit) and installs: code + Python environment under
   `/opt/asus-fingerprint`, config `/etc/asus-fp/config.json`, udev rule (sensor access without root),
   polkit policy, the `asus-fp` system service (runs as its own unprivileged user), the lock-screen PAM hook (`/etc/pam.d/kde-fingerprint`,
   derived from your distro's own vendor file; a pre-existing one is backed up), and a menu entry.
2. **Flash firmware…** – only shown if the sensor still runs stock firmware. Read the full-screen
   warning: **flashing permanently disables the sensor for Windows.** Type the exact confirmation text;
   anything else closes the app. Details in `docs/FLASHING.md`.
3. **Calibrate** – finger off the sensor; picks the sensor gain for your unit and records a 1000-frame
   blank background and noise mask (about a minute).
4. **Enroll (5)** – five presses, lift between them, vary the spot a little. **Add 5 more** appends to the
   existing enrollment. The number of presses per round (5/10/20/50) can be changed under **Options**.
   Aim for about 50 templates in total: the sensor only sees a 3 mm patch per press, and in testing
   ~50 templates matched far more reliably than ~20 (the store keeps up to 100).
   Saving asks for your password: the enrollment is stored root-owned and encrypted so nothing running as
   your user can alter what the lock screen trusts.
5. **Test** – shows the live sensor image, `is finger detected`, and MATCH OK / NO MATCH.
6. Lock the screen (Meta+L), wake it (move the mouse), rest your finger on the power button about a second.

**Delete enrollment** removes the stored templates (lock screen falls back to password only).
**Uninstall** removes everything except stored enrollments and restores the previous PAM file.

## How it runs

- `asus-fp.service` is a small system service running as its own unprivileged user (`asus-fp`) from
  boot. It is the only non-root process with access to the sensor. systemd decrypts the enrollment for it (`LoadCredentialEncrypted=`) straight into the service's
  private memory; no user process ever sees the templates. It answers verification requests on
  `/run/asus-fp/sock`; a request can only verify the user who sent it (socket peer credentials).
- The lock screen runs `pam_exec` → `/opt/asus-fingerprint/bin/asus-fp-pam` (standard library only,
  ~50 ms) which relays the service's prompts ("touch the power button", "not recognised – try again")
  and succeeds only on a confirmed match. It dies with the lock screen, so a password unlock frees the
  sensor immediately.
- The sensor is opened only while verifying or enrolling, and TLS to the sensor is terminated inside the
  process (no helper processes, no ports).

## Security notes (honest version)

- **Only the service touches the sensor.** In V1.2 the udev rule gives the sensor to the `asus-fp`
  system user alone; desktop programs (including this app) cannot open it. Calibrate, Enroll, Add more
  and Test are requests to the service, which captures and matches itself.
- **No scores leave the service.** Test and the lock screen get only "match / no match"; per-frame scores
  go to the service journal (`journalctl -u asus-fp`, readable by admins). The app shows live preview
  images only while you are enrolling or testing.
- Enrollment data at rest (`/var/lib/asus-fp/<user>.cred`, root-only): a **systemd credential sealed to the
  TPM2** plus the machine's host secret. Only systemd decrypts it, only for the service. Without a TPM2 the
  host key is used; without `systemd-creds` a root-only plaintext file (the app says which).
- Saving or deleting an enrollment, flashing and installing all require your password **every time**
  (polkit `auth_admin`, no 5-minute grace). The captured enrollment is handed from the service to the root
  helper through a file only the service user can write.
- The lock-screen helper verifies it is talking to the real service (socket peer credentials) and only
  succeeds on a confirmed match. The service validates every request, survives malformed ones and is
  restarted automatically.
- Python dependencies are installed with exact versions and SHA-256 hashes (Python 3.12+).
- Limits: no liveness detection; the matcher was validated on one person's fingers. A fingerprint is a
  convenience on top of a strong password, not a replacement for it.

## Troubleshooting

- *No fingerprint prompt on the lock screen*: `systemctl status asus-fp`; wake the lock screen
  (it starts the check when its UI is active); check `/etc/pam.d/kde-fingerprint` exists and names
  `asus-fp-pam`.
- *"sensor not accessible"*: run Install (udev rule), then unplug/replug is not possible – reboot once.
- *Matches are inconsistent*: add more enrollments ("Add 5 more"), place the finger the way you do when
  unlocking, re-run Calibrate if the laptop's temperature changed a lot.
- *Sensor shows "unknown firmware"*: unsupported variant; ask in the community chat.

## Files

| path | purpose |
|---|---|
| `asus_fp/sensor.py` | USB + in-process TLS-PSK capture, background/noise mask, finger detection |
| `asus_fp/matcher.py` | preprocessing, gain map, dense masked NCC, decision rule |
| `asus_fp/calibrate.py` | per-unit DAC pick + 100-frame background |
| `asus_fp/firmware.py` | firmware probe, pinned download + SHA-256, guarded flash |
| `asus_fp/store.py` | encrypted enrollment store |
| `asus_fp/daemon.py` / `pam_client.py` | system service and PAM side |
| `asus_fp/admin.py` / `installer.py` | privileged helper (pkexec) and system install |
| `asus_fp/gui.py` | the app |
| `third_party/goodix_fp_dump/` | vendored MIT protocol code (see SOURCE.txt) |
