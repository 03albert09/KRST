#ifndef CHAIN_H
#define CHAIN_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "block.h"

#define CHAIN_MAX_BLOCKS 512

typedef enum {
    CHAIN_ACCEPTED_TIP = 0,
    CHAIN_SIDE_BRANCH,
    CHAIN_DUPLICATE,
    CHAIN_ORPHAN,
    CHAIN_INVALID,
    CHAIN_FULL,
    CHAIN_STORE_ERROR
} chain_result_t;

typedef struct {
    uint8_t  hash[KRST_HASH_SIZE]; // hash tipa
    uint64_t cumulative_work;      // praca całego łańcucha
    uint32_t height;               // wysokość tipa
    uint32_t timestamp;            // czas tipa
    uint32_t target;               // próg tipa
    uint16_t block_count;          // bloki w indeksie (z bocznymi)
} chain_tip_t;

// indeks w RAM z dziennika na flashu
esp_err_t chain_init(void);

// format dziennika, zostaje genesis
esp_err_t chain_reset(void);

// walidacja + zapis + indeks, może zmienić tip
chain_result_t chain_accept_block(const block_t *block, uint32_t now, bool clock_synced, block_result_t *out_reason);

// kopia tipa, bezpieczne z każdego zadania
void chain_get_tip(chain_tip_t *out_tip);

// id sieci (genesis + trudność)
void chain_get_network_id(uint8_t out_id[KRST_HASH_SIZE]);

// próg dla bloku na tym tipie
uint32_t chain_next_target(const chain_tip_t *tip);

// hashe od tipa w tył, co raz rzadziej
uint16_t chain_build_locator(uint8_t out_hashes[][KRST_HASH_SIZE], uint16_t max_hashes);

// pierwszy hash z lokatora na naszym głównym łańcuchu
bool chain_find_common_height(const uint8_t hashes[][KRST_HASH_SIZE], uint16_t count, uint32_t *out_height);

// blok z głównego łańcucha po wysokości
bool chain_read_main_block(uint32_t height, block_t *out_block);

// nazwa wyniku do logów
const char *chain_result_str(chain_result_t result);

#endif
