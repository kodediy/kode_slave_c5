# Licences of kode_slave_c5

This file says which licence applies to each part of this repository. Read it before you distribute the firmware, or a firmware that you built from it.

The whole repository is under the Apache License, version 2.0. The file `LICENSE` holds its full text.

| Part | Owner |
|---|---|
| the files that Kode wrote: `main/kode_*`, `main/kir_wire.h`, `test/`, `tools/`, `pki/` | Kode |
| everything else: the slave example of esp-hosted-mcu, and the changes marked `KODE` in its files | Espressif Systems (the changes: Kode) |

Each source file says its licence in its first line (`SPDX-License-Identifier`).

## The code of Kode

Copyright (C) 2026 Kode.

Licensed under the Apache License, Version 2.0 (the "License"); you may not use these files except in compliance with the License. You may obtain a copy of the License at <https://www.apache.org/licenses/LICENSE-2.0>.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.

## esp-hosted-mcu

The rest of this repository is a copy of the slave example of [esp-hosted-mcu](https://github.com/espressif/esp-hosted-mcu), version 2.12.9. Its owner is Espressif Systems (Shanghai) Co., Ltd. `README.upstream.md` is the README of Espressif.

Kode changed some of these files for the Kode Dot. Each change is marked `KODE` in the code, and `README.md` lists them.

## Why this licence

kodeOS and the SDK are under the GNU General Public License, version 3 or later. This firmware is not: it runs on its own chip, the ESP32-C5, and the Kode Dot ships with that chip closed by Secure Boot, so only an image signed by Kode boots on it. The Apache License asks for no installation keys, and it is the licence of the code this firmware is built on. You can still build it, change it and run it on a C5 that has not been closed.

kodeOS carries a built copy of this firmware, `c5_slave.bin`, in the FAT of the board. That file is under the Apache License, version 2.0, like this repository.
