#ifndef MINER_H
#define MINER_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "block.h"
#include "chain.h"

// kandydat na następny blok (coinbase dla payout)
void miner_build_block(block_t *out_block, const chain_tip_t *tip,
                       const uint8_t payout[KRST_PUBKEY_SIZE], uint32_t now);

// próbuje max_hashes nonce, true = trafiony
bool miner_search(block_header_t *header, uint32_t max_hashes);

// kopie do skutku, false = stop albo zmiana tipa
bool miner_mine(block_t *candidate, const uint8_t tip_hash[KRST_HASH_SIZE], volatile const bool *stop);

// pomiar H/s
uint32_t miner_measure_hashrate(uint32_t duration_ms);

// zadanie górnika, nagrody na payout
esp_err_t miner_start(const uint8_t payout[KRST_PUBKEY_SIZE]);

// prośba o zatrzymanie
void miner_stop(void);

// czy górnik pracuje
bool miner_is_running(void);

#endif
