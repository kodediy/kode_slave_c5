<div align="center" markdown="1">

# kode_slave_c5

**The firmware of the ESP32-C5, the radio of the Kode Dot**

![Chip: ESP32-C5](https://img.shields.io/badge/chip-ESP32--C5-1f6feb)
[![esp-hosted-mcu 2.12.9](https://img.shields.io/badge/esp--hosted--mcu-2.12.9-E7352C?logo=espressif&logoColor=white)](https://github.com/espressif/esp-hosted-mcu)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-2ea44f)](NOTICE.md)

[kodeOS](https://github.com/kodediy/KodeOS) ·
[kode-sdk](https://github.com/kodediy/kode-sdk) ·
[The radio link](https://docs.kode.diy/sdk/kdrv/radio)

</div>

---

The ESP32-C5 is the only radio of the Kode Dot. It is a second processor next to the main processor, the ESP32-P4. This repository holds the firmware that runs on the C5. You need it to build that firmware or to write it to a board.

The firmware is the **slave** of esp-hosted-mcu, version 2.12.9, from Espressif. esp-hosted-mcu is software that lets one chip use the radio of another chip. The chip with the radio runs the slave. The chip that uses the radio is the **host**. Here the C5 is the slave and the P4 is the host. The two chips talk over the **link**, an SDIO bus (a bus made for SD cards) with esp-hosted on it.

This repository holds a copy of the slave example of the upstream project, the original project of Espressif. It adds the changes for the Kode Dot. For the documentation of Espressif, see `README.upstream.md`.

The host side is in [kode-sdk](https://github.com/kodediy/kode-sdk), which holds this repository as its submodule `c5/`. There, `kdrv_radio` and `AO_Radio` own the link. The pages [kdrv_radio](https://docs.kode.diy/sdk/kdrv/radio), [kdrv_c5](https://docs.kode.diy/sdk/kdrv/c5) and [AO_Radio](https://docs.kode.diy/sdk/kaos/radio) of the documentation describe the link, what the P4 reads of the C5, and the Active Object that owns them.

kodeOS uses this firmware as a binary. A release build goes to the file `storage_image/c5_slave.bin` of the KodeOS repository. The file travels to the board inside the internal FAT, the FAT file system in the flash of the board.

The host and the slave must run the **same esp-hosted version**. The host pins that version exactly: `espressif/esp_hosted ==2.12.9`. A change of the version on either side is a paired change. Make it on both sides, and make it on purpose.

## What the firmware changes for the Kode Dot

The code of the firmware adds five things. Each one is marked `KODE` in `main/esp_hosted_coprocessor.c`:

- **`KODE_SD`** configures IO6 as an input with its pull-up resistor on. IO6 is the card-detect line of the card slot. The P4 reads this line over the RPC GPIO expander. The expander is a service of esp-hosted. The P4 sends a request over the link, and the C5 reads or drives one of its pins. A request of this kind is a remote procedure call (RPC). The supply of the card is a pin of the P4 (`SD_PWR`, GPIO22). This firmware does not touch that pin.
- **`KODE_AUDIO`** drives IO4 high at boot. IO4 is wired to the enable input of the NS4150B speaker amplifier. So the C5 also controls the amplifier.
- **`KODE_X2`** measures the 32.768 kHz crystal at boot. It logs the error in ppm (parts per million). The number judges the load capacitors of the crystal (C38 and C44). The log line is how a board proves that its capacitors are right.
- **`KODE_IR`** starts the infrared service. IO24 (IR_TX) drives the infrared emitters, and IO23 (IR_RX) reads the infrared receiver. The service opens these pins only when the host first asks, through the peer data of esp-hosted. Peer data is a message with an id that esp-hosted carries between the two chips. The service is in `main/kode_ir.c`, and its messages are in `main/kir_wire.h`.
- **`KODE_SVC`** starts the KODE services. Three of them keep the secrets of the unit on the C5. The vault keeps the saved Wi-Fi networks and joins them itself, so no password goes back to the P4 (`main/kode_vault.c`). The identity is a key that the Key Manager makes and never lets out. It is the second key the Key Manager makes in a row, because its first random key after a reset comes from a small set of values. The key signs only its own certificate request and the login challenge of the Kode cloud (`main/kode_id.c`). The BLE bond keys stay here too: the P4 keeps tokens, and the C5 puts the real key into the two HCI commands that need it (`main/kode_btkeys.c`, `main/kode_hci_filter.c`). One task answers every request (`main/kode_svc.c`), and the messages are in `main/kode_wire.h`, the same file as in the SDK. The fourth service, Wi-Fi frames, is described below. The same task also answers the park request: the C5 keeps its Wi-Fi station associated, drops Bluetooth and the link, and waits for the next host (`main/kode_park.c`).

The end of `sdkconfig.defaults` adds two options to the defaults of Espressif:

- `CONFIG_ESP_SDIO_HOST_INTERFACE=y` selects SDIO for the link to the P4. The SDIO pins of the C5 are fixed in the chip.
- `CONFIG_ESP_HOSTED_ENABLE_GPIO_EXPANDER=y` turns on the RPC GPIO expander. With it, the P4 can read IO6 and drive IO4.

## Wi-Fi frames

The C5 listens to the air when the host asks. The host sends a start request with a channel, and the C5 turns on promiscuous mode. In this mode the radio hands up every frame it hears, not only the frames for itself. The service asks for management frames and data frames, never control frames, and it only receives: it builds no frame and calls no transmit function.

Every 100 ms in which it heard at least one frame, the C5 sends one event to the host. The event holds the number of management frames and of data frames heard in that period, the strongest signal level, the channel, and up to eight records of 25 bytes. A record holds the frame control, the first two addresses, the length of the frame on the air and the first eight bytes after the MAC header. The MAC header is the part of a frame that says who sent it and who it is for. A period with no frame sends nothing. The counts include every frame heard, also the ones that have no record.

The service never changes the station. It does not connect, disconnect or scan. While the station holds an association, the radio stays on the channel of the network, so a request for any other channel is refused and the service keeps what it was doing. A request with channel 0 listens where the radio is. A request while Wi-Fi is not started is refused too. The stop request turns promiscuous mode off, and so does the park request, before its answer.

At boot the C5 only registers the handler. The queue of 32 records and the task that sends the events are created by the first start request, and promiscuous mode is never on before one. The service is in `main/kode_sniff.c`, the record builder in `main/kode_sniff_rec.c` (its test runs on the host, `test/test_sniff_rec.c`), and the messages in `main/kode_wire.h`.

## Building

```bash
idf.py set-target esp32c5
idf.py build
```

**Result:** the file `build/kode_c5.bin` exists. It is about 1.3 MB.

In the KodeOS repository, the script `tools/build_c5.sh` builds the image into `build_c5/`. It then copies the image to `storage_image/c5_slave.bin`.

The project is named `kode_c5` on purpose. The image descriptor is a block at the start of the image, and it carries the project name. kodeOS reads that descriptor over the link (the driver `kdrv_c5`, the console command `c5` and the test `test component=c5`). The project name is the one fact that tells this build from the stock esp-hosted. The stock esp-hosted is the slave of Espressif with no changes. Its version RPC answers 2.12.9, the same as this build.

The partition table of the C5 is `partitions.esp32c5.csv`. It has two slots for the firmware, A and B: `ota_0` and `ota_1`, each of 1.9 MB. It also has the partition `otadata`, which records which slot starts. So an update over the link from the P4 writes the slot that is not running. It does not overwrite the running image.

## The closed build

The production line writes a closed image. Its first boot turns on secure boot and flash encryption and burns the eFuses of the C5 for good. The extra lines are in `sdkconfig.defaults.closed`:

```bash
idf.py -B build_closed -DSDKCONFIG=build_closed/sdkconfig \
  -DSDKCONFIG_DEFAULTS="sdkconfig.defaults;sdkconfig.defaults.esp32c5;sdkconfig.defaults.closed" \
  set-target esp32c5 build
tools/check_image.sh build_closed closed
```

**Result:** `build_closed/` holds the bootloader, the table, otadata and `kode_c5.bin`, all unsigned, and `flasher_args.json` lists all four. The check says the bootloader fits under the table once it is signed.

- Secure Boot V2 with RSA-3072. ESP-IDF marks ECDSA secure boot insecure on the C5.
- The build holds no key. The bootloader and the app are signed afterwards, and only signed files reach the line.
- Flash encryption in release mode, with a key that the C5 makes on its first boot. After that boot, the ROM answers only in Secure Download Mode.
- The free key slots stay free for a key added later. The bootloader of ESP-IDF 6.0.2 revokes them anyway on the first boot; a bootloader of ESP-IDF 6.1 leaves them.
- The bootloader logs at INFO, so the line can read that the C5 closed.

A release signs the closed build. The maintainer builds it with ESP-IDF 6.1 and sends the bootloader and the app to the factory's signing service, which signs them with its two HSM keys. `tools/sign_closed.py` checks what comes back against the two public keys in `pki/`; their digests are what every closed C5 holds in eFuse:

| Key | eFuse digest |
|---|---|
| `pki/c5-secure-boot-1.pem` | `f348453039c9081b97c2bb0f43788ce1f7c5cab84f5fa7ad672ef529b187997d` |
| `pki/c5-secure-boot-2.pem` | `952470ca989115379d76ce3846e6e0a36eb7fc401b5e83e4186e1361853671b8` |

The release carries `kode_c5-closed-<tag>.zip`: the folder the line's station downloads and writes to a virgin C5. It also carries `kode_c5-closed.bin`, the signed app alone for an update over the link. A closed C5 takes an update only when the image is signed by one of those keys; anything else fails with `ESP_ERR_OTA_VALIDATE_FAILED` and the C5 keeps what it runs.

A closed image goes only to a C5 that has never been closed, by its test points, on the line. An open C5 that receives the closed app over the link aborts at boot (`SECURE_FLASH_CHECK_ENC_EN_IN_APP`). Never write the closed bootloader to a C5 to try it: its first boot closes the chip.

## Three ways to write the firmware to the C5

The board has no USB connection to the C5. There are three ways, in order of preference:

1. **Over the link, from a running kodeOS.** This is the field path: the way for a board that is already in use. The host sends this image through the functions `esp_hosted_slave_ota_*`. The C5 then restarts in the other slot.
2. **The P4 as the programmer.** This is the lab path. It needs three wires, soldered from the pads of the C5 to the header J3. The pads are the small copper contacts of the C5 on the board. Kode's lab project `c5_flasher`, which is not public, drives the library esp-serial-flasher over UART1, a serial port. That project embeds four binaries of the C5. It writes the partition table at 0xc000 and ota_data at 0x16000, and not at the addresses of the third way.
3. **Directly on the pads.** This is the production path. Use `esptool` and a fixture, a holder that connects to the pads. The addresses are: bootloader at 0x2000, partition table at 0x10000, ota_data at 0x18000 and app at 0x20000.

## What the host can tell about this build

The version RPC answers the version of esp-hosted. It always sets the revision, the prerelease and the build to -1. It does this on a Kode build and on a stock build alike.

The image descriptor tells the two builds apart. The function `esp_hosted_get_coprocessor_app_desc()` returns these values:

- the `project_name` (`kode_c5`);
- the `PROJECT_VER` (`2.12.9`, read from `main/esp_hosted_coprocessor_fw_ver.h`);
- the IDF version;
- the build date, the build time and the ELF sha256, only when the slave is built with the option `CONFIG_ESP_HOSTED_ALLOW_FULL_APP_DESC`. The defaults of this firmware do not set it, and its default is off. The ELF sha256 is a fingerprint of the build.

The production row for the C5 requires `project_name == "kode_c5"`. A row is one hardware check of the production test. The row logs the other values as the record of the unit.

## Rollback

The open build does not use rollback. The option `CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE` is not set. The closed build sets it: a closed C5 has no pads recovery, so it marks a new image valid on the first KODE request from the P4 (`main/kode_svc.c`).

To use rollback, enable that option, and mark the running image valid once the transport is up. Then a bad OTA image falls back to the previous slot. An OTA image is an image that an update writes into the slot that is not running. It is bad when it writes without error but does not boot. Without rollback, a bad OTA image leaves the radio unusable.

## Take part

- **A bug or an idea:** open an issue here. Say which board and what `c5` prints on the console of kodeOS.
- **A change:** open an issue first, then a pull request. [CONTRIBUTING.md](https://github.com/kodediy/.github/blob/main/CONTRIBUTING.md) gives the rules. Before you push, run the tests of the parts that need no chip: `test/run.sh`. A change to the link is a change on both sides: say which pull request of kode-sdk goes with it.
- **A security problem:** do not open an issue. [SECURITY.md](https://github.com/kodediy/.github/blob/main/SECURITY.md) says where to write.

## Licence

Apache License, version 2.0 (`LICENSE`): the slave example of Espressif, its changes marked `KODE` and the files that Kode wrote. [NOTICE.md](NOTICE.md) says who owns each part, and why this repository is not under the GPL like kodeOS and the SDK.
