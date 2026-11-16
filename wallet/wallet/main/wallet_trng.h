#ifndef WALLET_TRNG_H
#define WALLET_TRNG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

void wallet_trng_enable(void);

void wallet_trng_disable(void);

void wallet_trng_fill(void *buf, size_t len);

int wallet_trng_mbedtls_cb(void *ctx, unsigned char *buf, size_t len);

#endif
