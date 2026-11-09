/* SPDX-License-Identifier: Apache-2.0 */
/**
 * @file kode_park.c
 * @brief The C5 parks (KODE_SELF_PARK): the station stays associated and
 *        everything that belonged to the leaving host is given up.
 */
#include "kode_park.h"

#include <stdbool.h>

#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_private/wifi.h"

#include "interface.h"
#include "kode_ir.h"
#include "kode_wire.h"
#if CONFIG_ESP_SDIO_HOST_INTERFACE
#include "sdio_slave_api.h"
#endif
#ifdef CONFIG_ESP_HOSTED_CP_BT
#include "esp_bt.h"
#include "slave_bt.h"
#endif

#define TAG "kode_park"

extern volatile uint8_t datapath;
extern volatile uint8_t station_connected;
extern interface_handle_t *if_handle;

static volatile bool s_armed;    /* a request said yes; kode_park_now() acts */
static volatile bool s_parked;   /* parked, waiting for a host              */

uint8_t kode_park_request(void)
{
    if ( 0U == station_connected )
    {
        ESP_LOGI(TAG, "no station associated: nothing to park");
        return KODE_ST_REFUSED;
    }
    s_armed = true;
    return KODE_ST_OK;
}

/** @brief Bluetooth off, when the host started the controller. A C5 whose
 *         BLE was never brought up has nothing to stop. */
static void park_bluetooth(void)
{
#ifdef CONFIG_ESP_HOSTED_CP_BT
    esp_bt_controller_status_t status = esp_bt_controller_get_status();

    if ( ESP_BT_CONTROLLER_STATUS_ENABLED == status )
    {
        (void)disable_bluetooth();
        status = esp_bt_controller_get_status();
    }
    if ( ESP_BT_CONTROLLER_STATUS_INITED == status )
    {
        (void)deinit_bluetooth(false);
    }
#endif
}

/** @brief The expansion supply pin back to an input with no pull of its own,
 *         so the board's pull-up (R72) holds the J3 supply on, as at reset. */
static void park_expansion_pin(void)
{
    gpio_config_t const j3 = {
        .pin_bit_mask = ((uint64_t)1U << KODE_PARK_PIN_J3),
        .mode         = GPIO_MODE_INPUT,
        .pull_up_en   = GPIO_PULLUP_DISABLE,
        .pull_down_en = GPIO_PULLDOWN_DISABLE,
        .intr_type    = GPIO_INTR_DISABLE,
    };

    if ( gpio_config(&j3) != ESP_OK )
    {
        ESP_LOGW(TAG, "IO%u would not go back to an input", (unsigned)KODE_PARK_PIN_J3);
    }
}

void kode_park_now(void)
{
    bool linked = false;

    if ( !s_armed )
    {
        return;
    }
    s_armed = false;

    /* The host-bound side first: the link is what the next P4 relies on. */
    (void)esp_wifi_internal_reg_rxcb(WIFI_IF_STA, NULL);

    /* What ESP_CLOSE_DATA_PATH does. Nothing waits in a queue for the host
     * (the transmit path is not queued): with the data path closed and the
     * C5 parked, process_tx_pkt() drops every host-bound packet at once. */
    datapath = 0U;
    if ( (NULL != if_handle) && (DEACTIVE < if_handle->state) )
    {
        if_handle->state = DEACTIVE;
    }

#if CONFIG_ESP_SDIO_HOST_INTERFACE
    /* The answer is the last frame the host gets: let it leave first. */
    if ( !sdio_tx_drained(KODE_PARK_TX_MS) )
    {
        ESP_LOGW(TAG, "the answer did not leave within %u ms", (unsigned)KODE_PARK_TX_MS);
    }
    linked = (sdio_park() == ESP_OK);
#endif
    if ( linked )
    {
        s_parked = true;
    }
    else
    {
        ESP_LOGE(TAG, "the SDIO slave would not reset: not parked");
    }

    /* What can stall comes last: the Bluetooth teardown waits on the controller. */
    kode_ir_park();
    park_expansion_pin();
    park_bluetooth();
    if ( linked )
    {
        ESP_LOGI(TAG, "parked: Wi-Fi kept, BT off, SDIO reset");
    }
}

bool kode_park_is_parked(void)
{
    return s_parked;
}

void kode_park_resume(void)
{
    s_parked = false;
    ESP_LOGI(TAG, "un-parked: a host is back");
}
