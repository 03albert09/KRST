#ifndef CHAIN_TASK_H
#define CHAIN_TASK_H

#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "esp_err.h"
#include "block.h"
#include "chain.h"
#include "node_p2p.h"

#define CHAIN_SOURCE_LOCAL ((p2p_peer_ref_t){ .slot = -1, .conn_id = 0 })

// wynik bloku -> chain_net
typedef void (*chain_task_result_fn)(const block_t *block, chain_result_t result, block_result_t reason,
                                     p2p_peer_ref_t source, bool relay);

// praca wykonywana w zadaniu łańcucha
typedef void (*chain_task_work_fn)(void *arg, p2p_peer_ref_t source);

// wywoływany co CHAIN_TASK_TICK_MS
typedef void (*chain_task_tick_fn)(TickType_t now);

#define CHAIN_TASK_TICK_MS 5000

typedef struct {
    bool (*clock_synced)(void);     // czy jest czas z SNTP
    chain_task_result_fn on_result; // reakcja na wynik bloku
    chain_task_tick_fn on_tick;     // co 5 s (timeouty sync)
} chain_task_config_t;

// kolejka + zadanie, jedyne zmieniające łańcuch
esp_err_t chain_task_start(const chain_task_config_t *config);

// blok do kolejki, zadanie robi free
bool chain_task_submit_block(block_t *block, p2p_peer_ref_t source, bool relay, TickType_t wait_ticks);

// funkcja do wykonania w zadaniu łańcucha
bool chain_task_post_work(chain_task_work_fn work, void *arg, p2p_peer_ref_t source, TickType_t wait_ticks);

#endif
