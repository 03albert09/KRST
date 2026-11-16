#ifndef LEDGER_H
#define LEDGER_H

#include <stdbool.h>
#include <stdint.h>
#include "block.h"

#define LEDGER_MAX_ACCOUNTS 64

// zeruje konta
void ledger_reset(void);

// czy odbiorca zmieści się w tabeli
bool ledger_can_apply_block(const block_t *block);

// dopisz nagrodę coinbase
void ledger_apply_block(const block_t *block);

// saldo adresu
uint64_t ledger_get_balance(const uint8_t address[KRST_PUBKEY_SIZE]);

#endif
