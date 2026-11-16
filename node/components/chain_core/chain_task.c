#include "chain_task.h"
#include <stdlib.h>
#include <time.h>
#include "freertos/task.h"
#include "freertos/queue.h"
#include "esp_log.h"
#include "node_crypto.h"

static const char *TAG = "CHAIN_TASK";

#define CHAIN_QUEUE_LENGTH  8
#define CHAIN_TASK_STACK    8192
#define CHAIN_TASK_PRIORITY 4

typedef struct {
    block_t *block;          // blok do sprawdzenia, NULL = praca
    bool relay;              // rozesłać po akceptacji
    chain_task_work_fn work; // funkcja do wykonania
    void *work_arg;          // jej argument (work zwalnia)
    p2p_peer_ref_t source;   // nadawca albo LOCAL
} chain_event_t;

static QueueHandle_t s_queue = NULL;
static chain_task_config_t s_config;

// Zapis wyniku w logu
static void log_result(const block_t *block, chain_result_t result, block_result_t reason) {
    unsigned long height = block->header.height;

    switch (result) {
        case CHAIN_ACCEPTED_TIP: {
            uint8_t hash[KRST_HASH_SIZE];
            char hash_hex[17];
            char recipient_hex[17];
            block_header_hash(&block->header, hash);
            node_crypto_bin_to_hex(hash, 8, hash_hex, sizeof(hash_hex));
            node_crypto_bin_to_hex(block->txs[0].recipient, 8, recipient_hex, sizeof(recipient_hex));
            ESP_LOGI(TAG, "Nowy tip: wysokosc %lu, hash %s..., nagroda %lu dla %s...", height, hash_hex,
                     (unsigned long)block->txs[0].amount, recipient_hex);
            break;
        }
        case CHAIN_DUPLICATE:
            ESP_LOGD(TAG, "Znany blok: wysokosc %lu", height);
            break;
        case CHAIN_INVALID:
            ESP_LOGW(TAG, "Odrzucono blok (wysokosc %lu): %s", height, block_result_str(reason));
            break;
        default:
            ESP_LOGW(TAG, "Blok (wysokosc %lu): %s", height, chain_result_str(result));
            break;
    }
}

// Przetworzenie jednego bloku
static void process_block(const chain_event_t *event) {
    uint32_t now = (uint32_t)time(NULL);
    bool clock_synced = s_config.clock_synced != NULL && s_config.clock_synced();

    block_result_t reason = BLOCK_OK;
    chain_result_t result = chain_accept_block(event->block, now, clock_synced, &reason);
    log_result(event->block, result, reason);

    if (s_config.on_result != NULL) {
        s_config.on_result(event->block, result, reason, event->source, event->relay);
    }
    free(event->block);
}

// Przetwarzanie kolejki i okresowe sprawdzenia
static void chain_task(void *arg) {
    (void)arg;
    TickType_t last_tick = xTaskGetTickCount();

    while (1) {
        chain_event_t event;
        if (xQueueReceive(s_queue, &event, pdMS_TO_TICKS(CHAIN_TASK_TICK_MS)) == pdTRUE) {
            if (event.block != NULL) {
                process_block(&event);
            } else {
                event.work(event.work_arg, event.source);
            }
        }

        TickType_t now = xTaskGetTickCount();
        if (now - last_tick >= pdMS_TO_TICKS(CHAIN_TASK_TICK_MS)) {
            last_tick = now;
            if (s_config.on_tick != NULL) {
                s_config.on_tick(now);
            }
        }
    }
}

// Uruchomienie zadania łańcucha
esp_err_t chain_task_start(const chain_task_config_t *config) {
    if (s_queue != NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    s_queue = xQueueCreate(CHAIN_QUEUE_LENGTH, sizeof(chain_event_t));
    if (s_queue == NULL) {
        return ESP_ERR_NO_MEM;
    }

    s_config = *config;
    if (xTaskCreate(chain_task, "chain", CHAIN_TASK_STACK, NULL, CHAIN_TASK_PRIORITY, NULL) != pdPASS) {
        vQueueDelete(s_queue);
        s_queue = NULL;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

// Przekazanie bloku do kolejki
bool chain_task_submit_block(block_t *block, p2p_peer_ref_t source, bool relay, TickType_t wait_ticks) {
    if (s_queue == NULL || block == NULL) {
        return false;
    }

    chain_event_t event = { .block = block, .relay = relay, .source = source };
    return xQueueSend(s_queue, &event, wait_ticks) == pdTRUE;
}

// Zlecenie pracy zadaniu łańcucha
bool chain_task_post_work(chain_task_work_fn work, void *arg, p2p_peer_ref_t source, TickType_t wait_ticks) {
    if (s_queue == NULL || work == NULL) {
        return false;
    }

    chain_event_t event = { .work = work, .work_arg = arg, .source = source };
    return xQueueSend(s_queue, &event, wait_ticks) == pdTRUE;
}
