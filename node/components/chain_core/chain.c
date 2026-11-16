#include "chain.h"
#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "mbedtls/sha256.h"
#include "block_store.h"
#include "consensus.h"
#include "ledger.h"

static const char *TAG = "CHAIN";

#define NO_PARENT (-1)

typedef struct {
    uint8_t  hash[KRST_HASH_SIZE]; // szukanie po hashu
    uint64_t cumulative_work;      // wybór tipa
    uint32_t height;               // indeks w s_main
    uint32_t timestamp;            // reguły dla dziecka
    uint32_t target;               // reguły dla dziecka
    uint32_t store_offset;         // gdzie blok na flashu
    int16_t  parent;               // indeks rodzica, -1 = genesis
} chain_entry_t;

static chain_entry_t *s_index = NULL;
static int s_count = 0;
static int s_tip = 0;

static int16_t *s_main = NULL;

static SemaphoreHandle_t s_tip_lock = NULL;
static chain_tip_t s_tip_snapshot;
static uint8_t s_network_id[KRST_HASH_SIZE];

// Udostępnienie aktualnego tipa innym zadaniom
static void publish_tip(void) {
    const chain_entry_t *tip = &s_index[s_tip];

    xSemaphoreTake(s_tip_lock, portMAX_DELAY);
    memcpy(s_tip_snapshot.hash, tip->hash, KRST_HASH_SIZE);
    s_tip_snapshot.cumulative_work = tip->cumulative_work;
    s_tip_snapshot.height = tip->height;
    s_tip_snapshot.timestamp = tip->timestamp;
    s_tip_snapshot.target = tip->target;
    s_tip_snapshot.block_count = (uint16_t)s_count;
    xSemaphoreGive(s_tip_lock);
}

// Wyszukanie bloku po hashu, od najnowszych
static int find_entry(const uint8_t hash[KRST_HASH_SIZE]) {
    for (int i = s_count - 1; i >= 0; i--) {
        if (memcmp(s_index[i].hash, hash, KRST_HASH_SIZE) == 0) {
            return i;
        }
    }
    return -1;
}

// Dane wpisu potrzebne regułom konsensusu dla jego dziecka
static consensus_parent_t entry_as_parent(int index) {
    consensus_parent_t parent = {
        .height = s_index[index].height,
        .timestamp = s_index[index].timestamp,
        .target = s_index[index].target,
    };
    return parent;
}

// Sprawdzenie, czy blok zmieści się w indeksie, a jako nowy tip także w tabeli kont
static bool has_room(const block_t *block, int parent) {
    return s_count < CHAIN_MAX_BLOCKS && (parent != s_tip || ledger_can_apply_block(block));
}

// Dopisanie bloku do indeksu. Blok przedłużający tip zostaje nowym tipem i zmienia salda.
static bool add_entry(const uint8_t hash[KRST_HASH_SIZE], const block_t *block, int parent, uint32_t offset) {
    const block_header_t *header = &block->header;
    chain_entry_t *entry = &s_index[s_count];
    memcpy(entry->hash, hash, KRST_HASH_SIZE);
    entry->cumulative_work = s_index[parent].cumulative_work + consensus_block_work(header->target);
    entry->height = header->height;
    entry->timestamp = header->timestamp;
    entry->target = header->target;
    entry->store_offset = offset;
    entry->parent = (int16_t)parent;
    s_count++;

    if (parent == s_tip && entry->cumulative_work > s_index[s_tip].cumulative_work) {
        s_tip = s_count - 1;
        s_main[entry->height] = (int16_t)s_tip;
        ledger_apply_block(block);
        return true;
    }
    return false;
}

// Walidacja bloku, od najtańszych kontroli
static chain_result_t validate_block(const block_t *block, const uint8_t hash[KRST_HASH_SIZE],
                                     uint32_t now, bool clock_synced,
                                     int *out_parent, block_result_t *out_reason) {
    const block_header_t *header = &block->header;
    *out_reason = BLOCK_OK;

    if (find_entry(hash) >= 0) {
        return CHAIN_DUPLICATE;
    }
    if (!consensus_check_pow(hash, header->target)) {
        *out_reason = BLOCK_ERR_POW;
        return CHAIN_INVALID;
    }

    int parent = find_entry(header->prev_hash);
    if (parent < 0) {
        return CHAIN_ORPHAN;
    }

    consensus_parent_t parent_info = entry_as_parent(parent);
    block_result_t reason = consensus_check_header_context(header, &parent_info, now, clock_synced);
    if (reason == BLOCK_OK) reason = block_check_structure(block);
    if (reason == BLOCK_OK) reason = consensus_check_transactions(block);
    if (reason != BLOCK_OK) {
        *out_reason = reason;
        return CHAIN_INVALID;
    }

    *out_parent = parent;
    return CHAIN_ACCEPTED_TIP;
}

// Dodanie do indeksu bloku wczytanego z dziennika
static void load_block(const block_t *block, uint32_t offset, void *ctx) {
    (void)ctx;

    uint8_t hash[KRST_HASH_SIZE];
    block_header_hash(&block->header, hash);

    int parent = NO_PARENT;
    block_result_t reason;
    chain_result_t result = validate_block(block, hash, 0, false, &parent, &reason);
    if (result != CHAIN_ACCEPTED_TIP) {
        ESP_LOGW(TAG, "Pominieto blok z dziennika (0x%lx): %s, %s", (unsigned long)offset,
                 chain_result_str(result), block_result_str(reason));
        return;
    }
    if (!has_room(block, parent)) {
        ESP_LOGW(TAG, "Brak miejsca. Pominieto blok z dziennika (0x%lx).", (unsigned long)offset);
        return;
    }
    add_entry(hash, block, parent, offset);
}

// Powrót indeksu do samego bloku genesis
static void reset_index(void) {
    block_header_t genesis;
    consensus_genesis_header(&genesis);

    chain_entry_t *entry = &s_index[0];
    memset(entry, 0, sizeof(*entry));
    block_header_hash(&genesis, entry->hash);
    entry->cumulative_work = consensus_block_work(genesis.target);
    entry->height = genesis.height;
    entry->timestamp = genesis.timestamp;
    entry->target = genesis.target;
    entry->parent = NO_PARENT;

    s_count = 1;
    s_tip = 0;
    s_main[0] = 0;
    ledger_reset();
}

// Identyfikator sieci z genesis i trudności pierwszego bloku. Dziennik z innej sieci jest kasowany.
static void compute_network_id(uint8_t out_id[KRST_HASH_SIZE]) {
    consensus_parent_t genesis_info = entry_as_parent(0);
    uint32_t first_target = consensus_next_target(&genesis_info);

    uint8_t input[KRST_HASH_SIZE + sizeof(first_target)];
    memcpy(input, s_index[0].hash, KRST_HASH_SIZE);
    memcpy(input + KRST_HASH_SIZE, &first_target, sizeof(first_target));
    mbedtls_sha256(input, sizeof(input), out_id, 0);
}

// Wczytanie łańcucha z flasha
esp_err_t chain_init(void) {
    if (s_index == NULL) {
        s_index = malloc(CHAIN_MAX_BLOCKS * sizeof(chain_entry_t));
        if (s_index == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    if (s_main == NULL) {
        s_main = malloc(CHAIN_MAX_BLOCKS * sizeof(int16_t));
        if (s_main == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }
    if (s_tip_lock == NULL) {
        s_tip_lock = xSemaphoreCreateMutex();
        if (s_tip_lock == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    reset_index();

    compute_network_id(s_network_id);

    esp_err_t err = block_store_open(s_network_id, load_block, NULL);
    publish_tip();
    if (err != ESP_OK) {
        return err;
    }

    ESP_LOGI(TAG, "Lancuch wczytany: wysokosc %lu, znanych blokow %d",
             (unsigned long)s_index[s_tip].height, s_count);
    return ESP_OK;
}

// Skasowanie całego łańcucha
esp_err_t chain_reset(void) {
    esp_err_t err = block_store_format();
    if (err != ESP_OK) {
        return err;
    }
    reset_index();
    publish_tip();
    return ESP_OK;
}

// Pełna akceptacja bloku
chain_result_t chain_accept_block(const block_t *block, uint32_t now, bool clock_synced, block_result_t *out_reason) {
    uint8_t hash[KRST_HASH_SIZE];
    block_header_hash(&block->header, hash);

    int parent = NO_PARENT;
    block_result_t reason = BLOCK_OK;
    chain_result_t result = validate_block(block, hash, now, clock_synced, &parent, &reason);
    if (out_reason) {
        *out_reason = reason;
    }
    if (result != CHAIN_ACCEPTED_TIP) {
        return result;
    }

    if (!has_room(block, parent)) {
        return CHAIN_FULL;
    }

    uint32_t offset = 0;
    esp_err_t err = block_store_append(block, &offset);
    if (err == ESP_ERR_NO_MEM) {
        return CHAIN_FULL;
    }
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Blad zapisu bloku: %s", esp_err_to_name(err));
        return CHAIN_STORE_ERROR;
    }

    bool is_new_tip = add_entry(hash, block, parent, offset);
    publish_tip();
    return is_new_tip ? CHAIN_ACCEPTED_TIP : CHAIN_SIDE_BRANCH;
}

// Pobranie kopii aktualnego tipa
void chain_get_tip(chain_tip_t *out_tip) {
    xSemaphoreTake(s_tip_lock, portMAX_DELAY);
    *out_tip = s_tip_snapshot;
    xSemaphoreGive(s_tip_lock);
}

// Pobranie identyfikatora sieci
void chain_get_network_id(uint8_t out_id[KRST_HASH_SIZE]) {
    memcpy(out_id, s_network_id, KRST_HASH_SIZE);
}

// Wyznaczenie progu dla bloku przedłużającego podany tip
uint32_t chain_next_target(const chain_tip_t *tip) {
    consensus_parent_t parent = { .height = tip->height, .timestamp = tip->timestamp, .target = tip->target };
    return consensus_next_target(&parent);
}

// Zbudowanie lokatora bloków
uint16_t chain_build_locator(uint8_t out_hashes[][KRST_HASH_SIZE], uint16_t max_hashes) {
    uint16_t count = 0;
    uint32_t height = s_index[s_tip].height;
    uint32_t step = 1;

    while (count < max_hashes - 1 && height > 0) {
        memcpy(out_hashes[count], s_index[s_main[height]].hash, KRST_HASH_SIZE);
        count++;

        if (count >= 8) {
            step *= 2;
        }
        height = height > step ? height - step : 0;
    }

    memcpy(out_hashes[count], s_index[0].hash, KRST_HASH_SIZE);
    return count + 1;
}

// Znalezienie wspólnego przodka z lokatora
bool chain_find_common_height(const uint8_t hashes[][KRST_HASH_SIZE], uint16_t count, uint32_t *out_height) {
    for (uint16_t i = 0; i < count; i++) {
        int index = find_entry(hashes[i]);
        if (index < 0) {
            continue;
        }

        uint32_t height = s_index[index].height;
        if (height <= s_index[s_tip].height && s_main[height] == index) {
            *out_height = height;
            return true;
        }
    }
    return false;
}

// Odczyt bloku głównego łańcucha z flasha
bool chain_read_main_block(uint32_t height, block_t *out_block) {
    if (height == 0 || height > s_index[s_tip].height) {
        return false;
    }
    return block_store_read(s_index[s_main[height]].store_offset, out_block) == ESP_OK;
}

// Nazwa wyniku akceptacji do logów
const char *chain_result_str(chain_result_t result) {
    switch (result) {
        case CHAIN_ACCEPTED_TIP: return "CHAIN_ACCEPTED_TIP";
        case CHAIN_SIDE_BRANCH:  return "CHAIN_SIDE_BRANCH";
        case CHAIN_DUPLICATE:    return "CHAIN_DUPLICATE";
        case CHAIN_ORPHAN:       return "CHAIN_ORPHAN";
        case CHAIN_INVALID:      return "CHAIN_INVALID";
        case CHAIN_FULL:         return "CHAIN_FULL";
        case CHAIN_STORE_ERROR:  return "CHAIN_STORE_ERROR";
    }
    return "CHAIN_UNKNOWN";
}
