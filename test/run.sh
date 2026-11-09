#!/bin/sh
# The C5 firmware's pure parts, compiled and run on the host. No ESP-IDF.
#
# The tests are assert()s, so NDEBUG is undone whatever the environment sets.
# KODE_C5_CFLAGS adds flags, e.g. the sanitizers CI runs them under.
set -e
cd "$(dirname "$0")"
out="${TMPDIR:-/tmp}/kode_c5_tests"
mkdir -p "$out"
cc -std=c11 -Wall -Wextra -Werror -UNDEBUG ${KODE_C5_CFLAGS:-} -I../main test_vault_list.c ../main/kode_vault_list.c -o "$out/vault_list"
"$out/vault_list"
cc -std=c11 -Wall -Wextra -Werror -UNDEBUG ${KODE_C5_CFLAGS:-} -I../main test_id_nonce.c ../main/kode_id_nonce.c -o "$out/id_nonce"
"$out/id_nonce"
cc -std=c11 -Wall -Wextra -Werror -UNDEBUG ${KODE_C5_CFLAGS:-} -I../main test_hci_filter.c ../main/kode_hci_filter.c -o "$out/hci_filter"
"$out/hci_filter"
cc -std=c11 -Wall -Wextra -Werror -UNDEBUG ${KODE_C5_CFLAGS:-} -I../main test_id_serial.c ../main/kode_id_serial.c -o "$out/id_serial"
"$out/id_serial"
cc -std=c11 -Wall -Wextra -Werror -UNDEBUG ${KODE_C5_CFLAGS:-} -I../main test_svc_frame.c ../main/kode_svc_frame.c -o "$out/svc_frame"
"$out/svc_frame"
cc -std=c11 -Wall -Wextra -Werror -UNDEBUG ${KODE_C5_CFLAGS:-} -I../main test_btkeys_cache.c ../main/kode_btkeys_cache.c -o "$out/btkeys_cache"
"$out/btkeys_cache"
