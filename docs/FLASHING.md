# Flashing the Goodix 27c6:521d to the community firmware (manual instructions)

**Read this first: flashing WILL permanently disable the fingerprint sensor for Windows.** The stock
firmware (`GFUSB_GM168SEC_APP_100xx`) cannot be backed up or restored, so Windows Hello fingerprint will
never work on this laptop again, even after reinstalling Windows. Linux is the only place the sensor will
work afterwards, through this app or the community tools.

The flash is one-way for a second reason: the sensor only exposes its firmware-update commands from the
bootloader, which you only reach by erasing the application firmware. The app therefore:

1. Reads the current firmware version and pairing-key state (read-only).
2. Erases the stock firmware. The sensor reboots into its bootloader.
3. **Stops here if the bootloader is not `MILAN_GM168SEC_IAP_10007`.** Nothing else is written; the sensor
   stays in bootloader mode and can still be flashed later by other means.
4. Writes the community pairing key (an all-zero PSK, so the Linux side can decrypt image frames).
5. Writes `GFUSB_GM168SEC_APP_10019` (25,200 bytes, SHA-256
   `6ff41957f387160c089559dffff6e8a26d1fa344d01bdaa6d62c5dab61883804`) in 256-byte chunks and lets the
   sensor verify its HMAC. On any error it re-erases so the bootloader stays clean.
6. Resets the sensor and confirms the new version and key.

## Where the firmware comes from

The firmware is Goodix property and is not included in this app. It is downloaded at flash time from the
community repository at a pinned commit and verified against the SHA-256 above:

- Repository: https://github.com/goodix-fp-linux-dev/goodix-firmware (folder `52xd`)
- Protocol tools the app is built on: https://github.com/goodix-fp-linux-dev/goodix-fp-dump (MIT)
- Community chat (Discord) is linked from the goodix-fp-dump README.

## Doing it by hand instead

If you prefer the community's own script:

```sh
git clone --recurse-submodules https://github.com/goodix-fp-linux-dev/goodix-fp-dump.git
cd goodix-fp-dump
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
sudo python3 run_521d.py        # type the random code it shows to confirm
```

`run_521d.py` erases, writes the key and flashes without the bootloader guard this app adds, and then
tries to capture one image with OpenSSL (that last step may fail on modern OpenSSL; it does not matter
for the flash). Afterwards run this app: it will report "community firmware - ready".

## If something goes wrong

- *"bootloader is '…', expected 'MILAN_GM168SEC_IAP_10007'"*: the app stopped before writing anything.
  Your sensor has a different bootloader than the community has seen; ask in the community chat before
  trying anything else. The sensor stays in bootloader mode (no fingerprint in any OS) until it is flashed.
- *Flash failed part-way*: the app re-erases and the sensor is back in bootloader mode; simply run the
  flash again.
- The sensor is powered through USB internally; a reboot of the laptop power-cycles it.
