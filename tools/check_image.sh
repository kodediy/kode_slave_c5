#!/usr/bin/env bash
#
# Checks a finished C5 build against what kodeOS and the board need of it:
#
#   - the image fits an OTA slot, read from the partition table it was built
#     with (a warning past 90 %: the next feature may not fit);
#   - the project is named kode_c5, which is how kodeOS tells this firmware
#     from a stock esp-hosted slave (`c5`'s recog=kode) - a rename would build,
#     flash and run, and kodeOS would no longer recognise it;
#   - the Kconfig lines the firmware is built around are set, because an
#     option that silently drops out of a configuration still builds.
#
#   usage: tools/check_image.sh <build_dir> [closed]
#   exit:  0 all checks hold, 1 one does not (::error:: lines say which)
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1

build="${1:?usage: tools/check_image.sh <build_dir> [closed]}"
variant="${2:-kode}"

# Past this share of the slot the size check warns.
WARN_PERCENT=90
# The closed bootloader's room: from its offset to the partition table, less
# the sector its Secure Boot V2 signature takes.
BOOTLOADER_OFFSET=$((0x2000))
TABLE_OFFSET=$((0x10000))
SIGNATURE_SECTOR=$((0x1000))

fail=0
error() { echo "::error::$1" >&2; fail=1; }

image="$build/kode_c5.bin"
desc="$build/project_description.json"
config="$build/config/sdkconfig.json"
table="partitions.esp32c5.csv"

for f in "$image" "$desc" "$config" "$table"; do
    if [ ! -f "$f" ]; then
        error "missing $f - is $build a finished build?"
        exit 1
    fi
done

# The slot's size, from the table's ota_0 line: name, type, subtype, offset, size.
slot_hex="$(awk -F, '$1 ~ /^[[:space:]]*ota_0[[:space:]]*$/ { gsub(/[[:space:]]/, "", $5); print $5 }' "$table")"
if [ -z "$slot_hex" ]; then
    error "no ota_0 line in $table"
    exit 1
fi
slot=$((slot_hex))
size="$(wc -c < "$image" | tr -d ' ')"
percent=$((size * 100 / slot))
if [ "$size" -gt "$slot" ]; then
    error "kode_c5.bin is $size bytes, the OTA slot $slot ($slot_hex)"
elif [ "$percent" -ge "$WARN_PERCENT" ]; then
    echo "::warning::kode_c5.bin fills $percent % of its OTA slot ($size of $slot bytes)"
fi

name="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["project_name"])' "$desc")"
if [ "$name" != "kode_c5" ]; then
    error "the project is named '$name'; kodeOS recognises this firmware as kode_c5"
fi

# require <CONFIG name> <expected json value>
require() {
    local got
    got="$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])).get(sys.argv[2])))' "$config" "$2")"
    if [ "$got" != "$3" ]; then
        error "$1: $2 is $got, it must be $3"
    fi
}

require "the P4 link runs over SDIO" ESP_SDIO_HOST_INTERFACE true
require "BLE is a controller for the P4's host" BT_CONTROLLER_ONLY true
require "the identity's CSR can be written" MBEDTLS_X509_CSR_WRITE_C true
require "the P4 tells one build from another" ESP_HOSTED_ALLOW_FULL_APP_DESC true
# require_off <what> <CONFIG name>: off, whether its menu shows it or not
require_off() {
    local got
    got="$(python3 -c 'import json,sys; print(json.dumps(json.load(open(sys.argv[1])).get(sys.argv[2])))' "$config" "$2")"
    if [ "$got" != "false" ] && [ "$got" != "null" ]; then
        error "$1: $2 is $got, it must be off"
    fi
}

if [ "$variant" = "closed" ]; then
    require "a closed C5 rolls back an update that never reached the P4" BOOTLOADER_APP_ROLLBACK_ENABLE true
    require "a closed C5 encrypts its NVS" NVS_ENCRYPTION true
    require "a closed C5 boots only signed images" SECURE_BOOT_V2_ENABLED true
    require "the C5 signs with RSA (ECDSA is insecure on it)" SECURE_SIGNED_APPS_RSA_SCHEME true
    require "the build holds no key" SECURE_BOOT_BUILD_SIGNED_BINARIES false
    require "a closed C5 encrypts its flash" SECURE_FLASH_ENC_ENABLED true
    require "the encryption is for good" SECURE_FLASH_ENCRYPTION_MODE_RELEASE true
    require "the ROM keeps only Secure Download Mode" SECURE_ENABLE_SECURE_ROM_DL_MODE true
    require "the bootloader says the C5 closed" BOOTLOADER_LOG_LEVEL 3
    # The insecure menu is open for one option; every other one stays off.
    for option in SECURE_BOOT_ALLOW_ROM_BASIC SECURE_BOOT_ALLOW_JTAG \
                  SECURE_BOOT_ALLOW_SHORT_APP_PARTITION SECURE_BOOT_V2_ALLOW_EFUSE_RD_DIS \
                  SECURE_BOOT_SKIP_WRITE_PROTECTION_SCA SECURE_FLASH_UART_BOOTLOADER_ALLOW_ENC \
                  SECURE_FLASH_UART_BOOTLOADER_ALLOW_DEC SECURE_FLASH_UART_BOOTLOADER_ALLOW_CACHE \
                  SECURE_FLASH_REQUIRE_ALREADY_ENABLED SECURE_FLASH_SKIP_WRITE_PROTECTION_CACHE \
                  SECURE_INSECURE_ALLOW_DL_MODE; do
        require_off "a closed C5 keeps every protection" "$option"
    done

    # Signing pads the bootloader to a whole sector and adds the signature's:
    # both must end before the table.
    boot="$build/bootloader/bootloader.bin"
    boot_size="$(wc -c < "$boot" | tr -d ' ')"
    boot_signed=$(( (boot_size + SIGNATURE_SECTOR - 1) / SIGNATURE_SECTOR * SIGNATURE_SECTOR + SIGNATURE_SECTOR ))
    boot_room=$((TABLE_OFFSET - BOOTLOADER_OFFSET))
    if [ "$boot_signed" -gt "$boot_room" ]; then
        error "the bootloader signed is $boot_signed bytes, its room $boot_room"
    else
        printf 'ok    bootloader signed %s of %s bytes\n' "$boot_signed" "$boot_room"
    fi
fi

if [ "$fail" -eq 0 ]; then
    printf 'ok    %s: %s of %s bytes (%s %%), project %s\n' \
           "$variant" "$size" "$slot" "$percent" "$name"
fi
exit "$fail"
