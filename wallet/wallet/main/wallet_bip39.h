#ifndef WALLET_BIP39_H
#define WALLET_BIP39_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"

#define BIP39_WORD_COUNT        2048
#define BIP39_MNEMONIC_WORDS    12
#define BIP39_ENTROPY_BYTES     16
#define BIP39_MAX_WORD_LEN      10

// Generowanie 12 slow mnemonika z anteny
esp_err_t wallet_bip39_generate_mnemonic(char *out_mnemonic, size_t max_len);

// Weryfikacja poprawnosci slow i sumy kontrolnej
esp_err_t wallet_bip39_validate_mnemonic(const char *mnemonic);

// Wyprowadzenie klucza prywatnego ze slow mnemonika
esp_err_t wallet_bip39_mnemonic_to_private_key(const char *mnemonic, uint8_t out_privkey[32]);

#endif // WALLET_BIP39_H
