#pragma once
#include <stdint.h>
#include "block.h"
#include "chain_task.h"

void th_make_child(block_t *block, const uint8_t parent_hash[KRST_HASH_SIZE],
                   uint32_t parent_height, uint32_t parent_timestamp, uint8_t variant);

void th_finish(block_t *block);

void th_break_pow(block_t *block);

void th_fresh_chain(void);

void th_prepare_chain_task(void);

void th_set_result_forward(chain_task_result_fn forward);

void th_set_tick_forward(chain_task_tick_fn forward);

void th_wait_chain_idle(void);

void th_genesis_hash(uint8_t out_hash[KRST_HASH_SIZE]);
