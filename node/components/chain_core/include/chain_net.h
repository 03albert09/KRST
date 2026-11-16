#ifndef CHAIN_NET_H
#define CHAIN_NET_H

#include <stdbool.h>
#include <stdint.h>
#include "freertos/FreeRTOS.h"
#include "block.h"
#include "chain.h"
#include "node_p2p.h"

#define CHAIN_NET_MAX_LOCATOR 16
#define CHAIN_NET_BATCH_SIZE  16

typedef struct __attribute__((packed)) {
    uint8_t  network_id[KRST_HASH_SIZE]; // obca sieć = odrzuć
    uint8_t  tip_hash[KRST_HASH_SIZE];   // hash tipa nadawcy
    uint64_t cumulative_work;            // więcej niż my = sync
    uint32_t height;                     // wysokość tipa nadawcy
} chain_net_status_t;

typedef struct __attribute__((packed)) {
    uint16_t count;                                         // ile hashy
    uint8_t  hashes[CHAIN_NET_MAX_LOCATOR][KRST_HASH_SIZE]; // lokator: gęsto przy tipie, rzadko dalej
} chain_net_get_blocks_t;

typedef struct __attribute__((packed)) {
    uint8_t more; // 1 = proś o kolejną paczkę
} chain_net_blocks_end_t;

typedef struct {
    // do jednego peera
    bool (*send)(p2p_peer_ref_t peer, p2p_cmd_t cmd, const void *payload, uint32_t length);
    // do wszystkich poza exclude
    int (*broadcast)(p2p_cmd_t cmd, const void *payload, uint32_t length, const p2p_peer_ref_t *exclude);
    // rozłącz (zły blok)
    void (*disconnect)(p2p_peer_ref_t peer);
} chain_net_transport_t;

// podpięcie transportu (send/broadcast/disconnect)
void chain_net_init(const chain_net_transport_t *transport);

// nowy peer: wyślij mu nasz status
void chain_net_on_peer_authenticated(p2p_peer_ref_t peer);

// wiadomość od peera, false = rozłącz
bool chain_net_handle_message(p2p_peer_ref_t peer, uint16_t cmd, const uint8_t *payload, uint32_t length);

// co 5 s: sync utknął = pytaj wszystkich o status
void chain_net_tick(TickType_t now);

// po bloku: rozgłoś / sync / rozłącz
void chain_net_on_block_result(const block_t *block, chain_result_t result, block_result_t reason,
                               p2p_peer_ref_t source, bool relay);

#endif
