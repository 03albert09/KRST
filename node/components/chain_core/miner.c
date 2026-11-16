#include "miner.h"
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "chain_task.h"
#include "consensus.h"

static const char *TAG = "MINER";

#define MINER_TASK_STACK        4096
#define MINER_TASK_PRIORITY     1
#define MINER_BATCH_HASHES      512
#define MINER_ACCEPT_TIMEOUT_MS 10000
#define MINER_SUBMIT_TIMEOUT_MS 5000

static TaskHandle_t s_task = NULL;
static uint8_t s_payout[KRST_PUBKEY_SIZE];
static volatile bool s_stop_requested = false;
static volatile bool s_running = false;

// Zbudowanie kandydata na kolejny blok
void miner_build_block(block_t *out_block, const chain_tip_t *tip,
                       const uint8_t payout[KRST_PUBKEY_SIZE], uint32_t now) {
    memset(out_block, 0, sizeof(*out_block));

    block_header_t *header = &out_block->header;
    header->height = tip->height + 1;
    memcpy(header->prev_hash, tip->hash, KRST_HASH_SIZE);
    header->timestamp = now > tip->timestamp ? now : tip->timestamp + 1;
    header->target = chain_next_target(tip);

    out_block->tx_count = 1;
    krst_tx_t *coinbase = &out_block->txs[0];
    coinbase->type = KRST_TX_COINBASE;
    coinbase->nonce = header->height;
    memcpy(coinbase->recipient, payout, KRST_PUBKEY_SIZE);
    coinbase->amount = CONSENSUS_BLOCK_REWARD;

    block_merkle_root(out_block->txs, out_block->tx_count, header->merkle_root);
}

// Sprawdzenie porcji kolejnych wartości nonce
bool miner_search(block_header_t *header, uint32_t max_hashes) {
    uint8_t hash[KRST_HASH_SIZE];

    for (uint32_t i = 0; i < max_hashes; i++) {
        block_header_hash(header, hash);
        if (consensus_check_pow(hash, header->target)) {
            return true;
        }
        header->nonce++;
        if (header->nonce == 0) {
            return false;
        }
    }
    return false;
}

// Pomiar szybkości kopania
uint32_t miner_measure_hashrate(uint32_t duration_ms) {
    block_header_t header;
    memset(&header, 0, sizeof(header));

    uint64_t hashes = 0;
    int64_t start_us = esp_timer_get_time();
    int64_t end_us = start_us + (int64_t)duration_ms * 1000;

    while (esp_timer_get_time() < end_us) {
        miner_search(&header, MINER_BATCH_HASHES);
        hashes += MINER_BATCH_HASHES;
        vTaskDelay(1);
    }

    int64_t elapsed_us = esp_timer_get_time() - start_us;
    return (uint32_t)(hashes * 1000000 / (uint64_t)elapsed_us);
}

// Sprawdzenie, czy tip różni się od podanego hasha
static bool tip_differs(const uint8_t hash[KRST_HASH_SIZE]) {
    chain_tip_t tip;
    chain_get_tip(&tip);
    return memcmp(tip.hash, hash, KRST_HASH_SIZE) != 0;
}

// Oczekiwanie, aż łańcuch przetworzy wykopany blok
static bool wait_for_tip_change(const uint8_t old_tip[KRST_HASH_SIZE]) {
    for (int waited_ms = 0; waited_ms < MINER_ACCEPT_TIMEOUT_MS; waited_ms += 20) {
        if (tip_differs(old_tip)) {
            return true;
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    return false;
}

// Kopanie kandydata zbudowanego na tipie o podanym hashu
bool miner_mine(block_t *candidate, const uint8_t tip_hash[KRST_HASH_SIZE], volatile const bool *stop) {
    while (stop == NULL || !*stop) {
        if (miner_search(&candidate->header, MINER_BATCH_HASHES)) {
            return true;
        }
        if (candidate->header.nonce == 0) {
            return false;
        }

        vTaskDelay(1);

        if (tip_differs(tip_hash)) {
            return false;
        }
    }
    return false;
}

// Kopanie do czasu zatrzymania
static void mine_until_stopped(void) {
    block_t *candidate = malloc(sizeof(block_t));
    if (candidate == NULL) {
        ESP_LOGE(TAG, "Brak pamieci na blok");
        return;
    }

    while (!s_stop_requested) {
        chain_tip_t tip;
        chain_get_tip(&tip);

        miner_build_block(candidate, &tip, s_payout, (uint32_t)time(NULL));
        if (!miner_mine(candidate, tip.hash, &s_stop_requested)) {
            continue;
        }

        block_t *found = malloc(sizeof(block_t));
        if (found == NULL) {
            ESP_LOGE(TAG, "Brak pamieci na wykopany blok");
            break;
        }
        memcpy(found, candidate, sizeof(block_t));

        if (!chain_task_submit_block(found, CHAIN_SOURCE_LOCAL, true, pdMS_TO_TICKS(MINER_SUBMIT_TIMEOUT_MS))) {
            ESP_LOGW(TAG, "Kolejka lancucha pelna. Blok porzucony.");
            free(found);
            continue;
        }

        if (!wait_for_tip_change(tip.hash)) {
            ESP_LOGE(TAG, "Lancuch nie przyjal bloku. Zatrzymywanie gornika.");
            break;
        }
    }

    free(candidate);
}

// Zadanie górnika
static void miner_task(void *arg) {
    (void)arg;

    while (1) {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        ESP_LOGI(TAG, "Kopanie rozpoczete");
        mine_until_stopped();
        ESP_LOGI(TAG, "Kopanie zatrzymane");
        s_running = false;
    }
}

// Uruchomienie kopania
esp_err_t miner_start(const uint8_t payout[KRST_PUBKEY_SIZE]) {
    if (s_running) {
        return ESP_ERR_INVALID_STATE;
    }

    if (s_task == NULL &&
        xTaskCreate(miner_task, "miner", MINER_TASK_STACK, NULL, MINER_TASK_PRIORITY, &s_task) != pdPASS) {
        s_task = NULL;
        return ESP_ERR_NO_MEM;
    }

    memcpy(s_payout, payout, KRST_PUBKEY_SIZE);
    s_stop_requested = false;
    s_running = true;
    xTaskNotifyGive(s_task);
    return ESP_OK;
}

// Prośba o zatrzymanie kopania
void miner_stop(void) {
    s_stop_requested = true;
}

// Sprawdzenie, czy górnik pracuje
bool miner_is_running(void) {
    return s_running;
}
