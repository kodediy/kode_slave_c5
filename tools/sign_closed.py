#!/usr/bin/env python3
"""Signs a closed build with the factory's signing service and lays out the
folder the production line writes to a C5 by its test points.

    tools/sign_closed.py <build_dir> <out_dir>

The service (factory-link, POST /v1/c5/sign) holds the two Secure Boot V2
keys in an HSM and returns the image padded to 4 KB with one signature
sector: a block for each key. SIGN_TOKEN in the environment authorises the
call; SIGN_URL overrides the service's address. The token is never printed.

What comes back is checked before anything is written, for the bootloader
and the app alike:

  - the image itself is unchanged, padded with 0xFF to a whole sector, and
    followed by one signature sector;
  - the sector holds two blocks and no third, each with its magic, the
    SHA-256 of this image and its CRC;
  - block 0 carries the key of pki/c5-secure-boot-1.pem and block 1 that of
    pki/c5-secure-boot-2.pem - the digests every closed C5 holds in eFuse -
    and `espsecure verify-signature` accepts the image with each PEM.

<out_dir> then holds the build's flasher_args.json and flash_args, with the
signed bootloader and app and the unsigned table and otadata at the paths
those files name. Needs espsecure (esptool) on the PATH.

    exit: 0 signed and checked, 1 a check or the service failed
"""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
import zlib

SIGN_URL = "https://factory-link.kode.diy/v1/c5/sign"
PKI = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "pki")
KEYS = ("c5-secure-boot-1.pem", "c5-secure-boot-2.pem")
SECTOR = 4096
BLOCK = 1216                     # one Secure Boot V2 signature block
MAGIC = b"\xe7\x02"
DIGEST_AT, KEY_AT, KEY_END, CRC_AT = 4, 36, 812, 1196
SIGNED = ("bootloader/bootloader.bin", "kode_c5.bin")
COPIED = ("flasher_args.json", "flash_args",
          "partition_table/partition-table.bin", "ota_data_initial.bin")


class Refused(Exception):
    pass


def sign(url, token, image):
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/octet-stream"}
    # What the service records of each signature besides the token: the
    # commit and the run that asked, when a workflow asks.
    for header, var in (("X-Kode-Commit", "GITHUB_SHA"), ("X-Kode-Run", "GITHUB_RUN_ID")):
        if os.environ.get(var):
            headers[header] = os.environ[var]
    req = urllib.request.Request(url, data=image, method="POST", headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            return r.read()
    except urllib.error.HTTPError as e:
        raise Refused(f"the service answered {e.code}: {e.read()[:300].decode(errors='replace')}")


def key_digest(pem):
    """The eFuse digest of a public key, as espsecure computes it."""
    with tempfile.TemporaryDirectory() as tmp:
        digest = os.path.join(tmp, "digest.bin")
        subprocess.run(["espsecure", "digest-sbv2-public-key", "--keyfile", pem,
                        "--output", digest], check=True, stdout=subprocess.DEVNULL)
        return open(digest, "rb").read()


def check(name, plain, signed, path, digests):
    pad = -(-len(plain) // SECTOR) * SECTOR
    if len(signed) != pad + SECTOR:
        raise Refused(f"{name}: {len(signed)} bytes back, {pad + SECTOR} expected")
    if signed[:len(plain)] != plain:
        raise Refused(f"{name}: the image itself changed")
    if set(signed[len(plain):pad]) - {0xFF}:
        raise Refused(f"{name}: the padding is not 0xFF")
    image_digest = hashlib.sha256(signed[:pad]).digest()
    for i, (pem, want) in enumerate(zip(KEYS, digests)):
        b = signed[pad + i * BLOCK:pad + (i + 1) * BLOCK]
        if b[:2] != MAGIC:
            raise Refused(f"{name}: block {i} has no signature magic")
        if b[DIGEST_AT:DIGEST_AT + 32] != image_digest:
            raise Refused(f"{name}: block {i} signs another image")
        if int.from_bytes(b[CRC_AT:CRC_AT + 4], "little") != zlib.crc32(b[:CRC_AT]):
            raise Refused(f"{name}: block {i} fails its CRC")
        if hashlib.sha256(b[KEY_AT:KEY_END]).digest() != want:
            raise Refused(f"{name}: block {i} does not carry the key of {pem}")
        subprocess.run(["espsecure", "verify-signature", "--version", "2",
                        "--keyfile", os.path.join(PKI, pem), path],
                       check=True, stdout=subprocess.DEVNULL)
    if signed[pad + 2 * BLOCK:pad + 2 * BLOCK + 2] == MAGIC:
        raise Refused(f"{name}: a third signature block")


def main(argv):
    if len(argv) != 3:
        print(__doc__.split("\n\n")[1], file=sys.stderr)
        return 1
    build, out = argv[1], argv[2]
    token = os.environ.get("SIGN_TOKEN", "")
    if not token:
        print("::error::SIGN_TOKEN is not set", file=sys.stderr)
        return 1
    url = os.environ.get("SIGN_URL") or SIGN_URL
    digests = [key_digest(os.path.join(PKI, k)) for k in KEYS]
    try:
        for name in COPIED:
            os.makedirs(os.path.dirname(os.path.join(out, name)) or out, exist_ok=True)
            shutil.copyfile(os.path.join(build, name), os.path.join(out, name))
        for name in SIGNED:
            plain = open(os.path.join(build, name), "rb").read()
            signed = sign(url, token, plain)
            path = os.path.join(out, name)
            os.makedirs(os.path.dirname(path) or out, exist_ok=True)
            with open(path, "wb") as f:
                f.write(signed)
            check(name, plain, signed, path, digests)
            print(f"ok    {name}: {len(plain)} -> {len(signed)} bytes, "
                  f"signed by {KEYS[0]} and {KEYS[1]}")
    except (Refused, OSError, subprocess.CalledProcessError) as e:
        print(f"::error::{e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
