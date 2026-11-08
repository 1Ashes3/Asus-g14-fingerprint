"""Firmware state of the Goodix 27c6:521d and the one-time, guarded flash to the community firmware.

States (probe() is read-only):
  "community"  - running GFUSB_GM168SEC_APP_10019 with the community PSK: ready to use
  "stock"      - running a stock GFUSB_GM168SEC_APP_100xx firmware: flash required (one-way!)
  "bootloader" - MILAN_GM168SEC_IAP_10007: a previous flash was interrupted; flash can resume
  "unknown"    - anything else: refuse
The firmware binary is Goodix property and is never shipped; it is downloaded from the community
repository at a pinned commit and SHA-256 verified before anything is written."""
import hashlib
import hmac
import os
import re
import struct
import time
import urllib.request

from .vendor import goodix, protocol, c52

PID = 0x521D
FIRMWARE_URL = ("https://raw.githubusercontent.com/goodix-fp-linux-dev/goodix-firmware/"
                "7b9a828d1d14dee587d9c900505233188c23a92d/52xd/GFUSB_GM168SEC_APP_10019.bin")
FIRMWARE_SHA256 = "6ff41957f387160c089559dffff6e8a26d1fa344d01bdaa6d62c5dab61883804"
FIRMWARE_SIZE = 25200
MANUAL_URL = "https://github.com/goodix-fp-linux-dev/goodix-fp-dump"
CONFIRM_TEXT = "Yes, I am sure"


class FirmwareError(RuntimeError):
    pass


def _connect(timeout=15):
    dev = goodix.Device(PID, protocol.USBProtocol, timeout)
    dev.nop()
    return dev


def _reconnect(old=None):
    if old is not None:
        try:
            import usb.util
            usb.util.dispose_resources(old.protocol.device)
        except Exception:
            pass
    last = None
    for _ in range(6):
        try:
            return _connect()
        except Exception as e:
            last = e
            time.sleep(1)
    raise FirmwareError(f"could not reconnect to the sensor: {last}")


def _sync(dev):
    """Discard stale replies left in the device queue by an earlier (possibly killed) session."""
    for _ in range(6):
        try:
            dev.empty_buffer(); dev.nop(); time.sleep(0.3); dev.empty_buffer()
            return dev.firmware_version()
        except Exception:
            time.sleep(0.4)
    raise FirmwareError("could not sync with the sensor")


def _version(dev, tries=3):
    for _ in range(tries):
        try:
            return dev, _sync(dev)
        except Exception:
            time.sleep(1)
            try:
                dev = _reconnect(dev)
            except FirmwareError:
                pass
    raise FirmwareError("could not read the firmware version")


def _psk_ok(dev):
    r = dev.preset_psk_read(0xBB020001, len(c52.PMK_HASH), 0)
    return bool(r[0]) and r[1] == 0xBB020001 and r[2] == c52.PMK_HASH


class _Lock:
    def __enter__(self):
        from .sensor import acquire_lock
        self._l = acquire_lock()
        return self

    def __exit__(self, *exc):
        from .sensor import release_lock
        release_lock(self._l)


def probe():
    """Read-only. Returns dict(state, firmware, community_psk)."""
    with _Lock():
        return _probe_unlocked()


def _probe_unlocked():
    dev = _connect()
    try:
        dev, fw = _version(dev)
        psk = _psk_ok(dev)
    finally:
        try:
            import usb.util
            usb.util.dispose_resources(dev.protocol.device)
        except Exception:
            pass
    if fw == c52.TARGET_FIRMWARE and psk:
        state = "community"
    elif fw == c52.TARGET_FIRMWARE:
        state = "community-nopsk"
    elif re.fullmatch(c52.VALID_FIRMWARE, fw):
        state = "stock"
    elif fw == c52.IAP_FIRMWARE:
        state = "bootloader"
    else:
        state = "unknown"
    return {"state": state, "firmware": fw, "community_psk": psk}


def download_firmware(dest_dir, progress=None):
    """Download the pinned community firmware and verify its SHA-256. Returns the file path."""
    os.makedirs(dest_dir, exist_ok=True)
    path = os.path.join(dest_dir, "GFUSB_GM168SEC_APP_10019.bin")
    if progress:
        progress("downloading firmware from the community repository")
    req = urllib.request.Request(FIRMWARE_URL, headers={"User-Agent": "asus-fingerprint/1.1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(FIRMWARE_SIZE * 4)
    digest = hashlib.sha256(data).hexdigest()
    if len(data) != FIRMWARE_SIZE or digest != FIRMWARE_SHA256:
        raise FirmwareError(f"firmware download failed verification (size {len(data)}, sha256 {digest[:16]}...)")
    if c52.TARGET_FIRMWARE.encode() not in data:
        raise FirmwareError("firmware file does not contain the expected version string")
    with open(path, "wb") as f:
        f.write(data)
    if progress:
        progress("firmware verified (SHA-256 OK)")
    return path


def flash(firmware_path, confirm_text, progress=print):
    from . import hardware
    if not hardware.find_sensor():
        raise FirmwareError("Goodix 27c6:521d sensor not present - refusing to flash anything")
    with _Lock():
        return _flash_unlocked(firmware_path, confirm_text, progress)


def _flash_unlocked(firmware_path, confirm_text, progress=print):
    """Guarded one-way flash. Refuses unless confirm_text == CONFIRM_TEXT exactly.
    Sequence (from goodix-fp-dump driver_52xd, with guards): erase stock app -> bootloader must report
    MILAN_GM168SEC_IAP_10007 (else STOP before writing anything) -> write community PSK -> write +
    HMAC-verify firmware -> reset -> verify."""
    if confirm_text != CONFIRM_TEXT:
        raise FirmwareError("confirmation text did not match; nothing was done")
    firmware = open(firmware_path, "rb").read()
    if hashlib.sha256(firmware).hexdigest() != FIRMWARE_SHA256:
        raise FirmwareError("firmware file hash mismatch; nothing was done")

    dev = _connect()
    dev, version = _version(dev)
    progress(f"current firmware: {version}")
    if version == c52.TARGET_FIRMWARE:
        progress("already running the community firmware - refusing to erase")
        return {"state": "community", "firmware": version}

    if re.fullmatch(c52.VALID_FIRMWARE, version):
        progress("erasing stock firmware (one-way)...")
        try:
            dev.mcu_erase_app(50, True)
        except Exception as e:                      # MCU usually resets here
            progress(f"(usb reset during erase: {e})")
        time.sleep(1)
        dev, version = _version(dev)
        progress(f"after erase: {version}")

    if version != c52.IAP_FIRMWARE:
        raise FirmwareError(f"bootloader is '{version}', expected '{c52.IAP_FIRMWARE}'. STOPPED before writing "
                            "anything: PSK and flash untouched. The sensor stays in bootloader mode.")

    if not _psk_ok(dev):
        progress("writing community pairing key...")
        ok = dev.preset_psk_write(0xBB010003, c52.PSK_WHITE_BOX, 114, 0, bytes.fromhex("56a5bb956b7c8d9e0000"))
        if not ok or not _psk_ok(dev):
            raise FirmwareError("pairing key write failed; firmware NOT written")

    progress("writing firmware...")
    mod = bytes(range(1, 65))
    raw_pmk = (struct.pack(">H", len(c52.PSK)) + c52.PSK) * 2
    pmk = hashlib.sha256(raw_pmk).digest()
    pmk_hmac = hmac.new(pmk, mod, hashlib.sha256).digest()
    fw_hmac = hmac.new(pmk_hmac, firmware, hashlib.sha256).digest()
    try:
        for i in range(0, len(firmware), 256):
            if not dev.write_firmware(i, firmware[i:i + 256], 2):
                raise FirmwareError(f"write failed at offset {i:#x}")
        if not dev.check_firmware(None, None, None, fw_hmac):
            raise FirmwareError("firmware HMAC check failed")
    except Exception:
        progress("flash failed - re-erasing so the bootloader stays clean")
        try:
            dev.mcu_erase_app(50, True)
        except Exception:
            pass
        raise
    progress("firmware verified; resetting sensor")
    dev.reset(False, True, 50)
    try:
        dev.disconnect()
    except Exception:
        pass
    time.sleep(1)
    dev = _reconnect(dev)
    dev, version = _version(dev)
    psk = _psk_ok(dev)
    progress(f"now running {version}, community key {'present' if psk else 'MISSING'}")
    if version != c52.TARGET_FIRMWARE or not psk:
        raise FirmwareError(f"unexpected final state: {version}, psk={psk}")
    return {"state": "community", "firmware": version}
