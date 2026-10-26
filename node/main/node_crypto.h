#ifndef NODE_CRYPTO_H
#define NODE_CRYPTO_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "mbedtls/ecdsa.h"

void node_crypto_init(void);

bool node_crypto_get_pubkey(uint8_t out_pubkey[33]);

bool node_crypto_sign(const uint8_t hash[32], uint8_t out_sig[64]);

bool node_crypto_verify(const uint8_t pubkey[33], const uint8_t hash[32], const uint8_t sig[64]);

void node_crypto_compute_handshake_hash(const uint8_t chal_a[32], const uint8_t chal_b[32],
                                        const uint8_t pk_a[33], const uint8_t pk_b[33],
                                        uint8_t out_hash[32]);

bool node_crypto_compute_shared_secret(const uint8_t peer_pubkey[33], uint8_t out_secret[32]);

void node_crypto_derive_session_key(const uint8_t shared_secret[32],
                                    const uint8_t chal_a[32],
                                    const uint8_t chal_b[32],
                                    uint8_t out_session_key[32]);

void node_crypto_calc_msg_hmac(const uint8_t session_key[32],
                               uint16_t magic, uint16_t cmd, uint32_t length, uint32_t seq,
                               const void *payload, uint32_t payload_len,
                               uint8_t out_hmac[16]);

bool node_crypto_verify_msg_hmac(const uint8_t session_key[32],
                                 uint16_t magic, uint16_t cmd, uint32_t length, uint32_t seq,
                                 const void *payload, uint32_t payload_len,
                                 const uint8_t expected_hmac[16]);

void node_crypto_bin_to_hex(const uint8_t *data, size_t data_len, char *out_hex, size_t max_len);

#endif // NODE_CRYPTO_H
