#ifndef WALLET_TRNG_H
#define WALLET_TRNG_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

// Wlaczenie toru radiowego i stabilizacja szumu
void wallet_trng_enable(void);

// Wylaczenie toru radiowego i usypienie anteny
void wallet_trng_disable(void);

// Pobranie losowych bajtow z anteny Wi-Fi
void wallet_trng_fill(void *buf, size_t len);

// Callback losowosci antenowej dla mbed TLS
int wallet_trng_mbedtls_cb(void *ctx, unsigned char *buf, size_t len);

#endif // WALLET_TRNG_H
