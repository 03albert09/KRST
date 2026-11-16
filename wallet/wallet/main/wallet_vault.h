#ifndef WALLET_VAULT_H
#define WALLET_VAULT_H

#include "esp_err.h"
#include "wallet_types.h"

#define WALLET_MNEMONIC_MAX_LEN 256

esp_err_t wallet_vault_get_address(uint8_t out_address[WALLET_PUBKEY_SIZE]);

esp_err_t wallet_vault_generate_wallet(const char *password,
                                       char out_mnemonic[WALLET_MNEMONIC_MAX_LEN],
                                       uint8_t out_pub_key[WALLET_PUBKEY_SIZE]);

esp_err_t wallet_vault_recover_wallet(const char *mnemonic,
                                      const char *password,
                                      uint8_t out_pub_key[WALLET_PUBKEY_SIZE]);

esp_err_t wallet_vault_import_keys(const uint8_t priv_key[WALLET_PRIVKEY_SIZE],
                                   const uint8_t pub_key[WALLET_PUBKEY_SIZE],
                                   const char *password);

esp_err_t wallet_vault_create_signed_tx(uint64_t amount,
                                        const uint8_t recipient_pub[WALLET_PUBKEY_SIZE],
                                        const char *password,
                                        wallet_transaction_t *out_tx);

#endif