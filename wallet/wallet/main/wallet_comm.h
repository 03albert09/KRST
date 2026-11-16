#ifndef WALLET_COMM_H
#define WALLET_COMM_H

#include "esp_err.h"
#include "wallet_types.h"

void wallet_comm_init(void);

esp_err_t wallet_comm_send_tx(const wallet_transaction_t *tx, const char *target_ip);

#endif
