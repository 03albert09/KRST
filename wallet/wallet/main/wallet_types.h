#ifndef WALLET_TYPES_H
#define WALLET_TYPES_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#define WALLET_PRIVKEY_SIZE     32
#define WALLET_PUBKEY_SIZE      32  // 32 bajty (64 znaki HEX)
#define WALLET_HASH_SIZE        32  // SHA-256
#define WALLET_SIG_SIZE         64  // ECDSA secp256k1 (32B R + 32B S)

typedef struct __attribute__((packed)) {
    uint32_t nonce;                                 // 4 B  - licznik transakcji
    uint8_t  sender_pubkey[WALLET_PUBKEY_SIZE];     // 32 B - klucz publiczny nadawcy
    uint8_t  recipient_pubkey[WALLET_PUBKEY_SIZE];  // 32 B - klucz publiczny odbiorcy [y]
    uint64_t amount;                                // 8 B  - kwota [x]
    uint8_t  tx_hash[WALLET_HASH_SIZE];             // 32 B - SHA-256 z powyższych 76 bajtów
    uint8_t  signature[WALLET_SIG_SIZE];            // 64 B - podpis ECDSA secp256k1
} wallet_transaction_t;

#endif // WALLET_TYPES_H