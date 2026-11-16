#ifndef WALLET_TYPES_H
#define WALLET_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "krst_tx.h"

#define WALLET_PRIVKEY_SIZE     32
#define WALLET_PUBKEY_SIZE      KRST_PUBKEY_SIZE
#define WALLET_HASH_SIZE        KRST_HASH_SIZE
#define WALLET_SIG_SIZE         KRST_SIGNATURE_SIZE

typedef krst_tx_t wallet_transaction_t;

#endif
