#include "wallet_vault.h"
#include "wallet_bip39.h"
#include "wallet_trng.h"
#include <string.h>
#include <stdlib.h>
#include "esp_efuse.h"
#include "esp_efuse_table.h"
#include "nvs_flash.h"
#include "nvs.h"

#include "mbedtls/gcm.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/platform_util.h"

#define IV_SIZE             12
#define TAG_SIZE            16
#define SALT_SIZE           16
#define PBKDF2_ITERATIONS   50000

typedef struct __attribute__((packed)) {
    uint8_t priv_key[WALLET_PRIVKEY_SIZE];
    uint8_t pub_key[WALLET_PUBKEY_SIZE];
} vault_plain_t;

typedef struct __attribute__((packed)) {
    uint8_t iv[IV_SIZE];
    uint8_t salt[SALT_SIZE];
    uint8_t tag[TAG_SIZE];
    uint8_t ciphertext[sizeof(vault_plain_t)];
} vault_blob_t;

// Wyprowadzenie klucza szyfrujacego KEK z eFuse
static esp_err_t derive_hardware_kek(const char *password,
                                     const uint8_t salt[SALT_SIZE],
                                     uint8_t out_kek[32]) {
    uint8_t silicon_id[16] = {0};
    esp_err_t err = esp_efuse_read_field_blob(ESP_EFUSE_OPTIONAL_UNIQUE_ID, silicon_id, 128);
    if (err != ESP_OK) {
        return err;
    }

    size_t pass_len = strlen(password);
    size_t ikm_len = pass_len + sizeof(silicon_id);
    uint8_t *ikm = calloc(1, ikm_len);
    if (!ikm) {
        mbedtls_platform_zeroize(silicon_id, sizeof(silicon_id));
        return ESP_ERR_NO_MEM;
    }

    memcpy(ikm, password, pass_len);
    memcpy(ikm + pass_len, silicon_id, sizeof(silicon_id));

    int ret = mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
                                            ikm, ikm_len,
                                            salt, SALT_SIZE,
                                            PBKDF2_ITERATIONS,
                                            32, out_kek);

    mbedtls_platform_zeroize(ikm, ikm_len);
    mbedtls_platform_zeroize(silicon_id, sizeof(silicon_id));
    free(ikm);

    return (ret == 0) ? ESP_OK : ESP_FAIL;
}

// Wyliczenie klucza publicznego na secp256k1
static esp_err_t derive_pubkey_secp256k1(const uint8_t priv_key[WALLET_PRIVKEY_SIZE],
                                         uint8_t pub_key[WALLET_PUBKEY_SIZE]) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_mpi d;

    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi_init(&d);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
    if (ret == 0) ret = mbedtls_mpi_read_binary(&d, priv_key, WALLET_PRIVKEY_SIZE);
    if (ret == 0) ret = mbedtls_ecp_check_privkey(&grp, &d);
    
    wallet_trng_enable();
    if (ret == 0) ret = mbedtls_ecp_mul(&grp, &Q, &d, &grp.G, wallet_trng_mbedtls_cb, NULL);
    wallet_trng_disable();

    if (ret == 0) {
        size_t olen = 0;
        ret = mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_COMPRESSED,
                                             &olen, pub_key, WALLET_PUBKEY_SIZE);
        if (ret == 0 && olen != WALLET_PUBKEY_SIZE) {
            ret = -1;
        }
    }

    mbedtls_mpi_free(&d);
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);

    return (ret == 0) ? ESP_OK : ESP_FAIL;
}

// Podpisanie hasha transakcji algorytmem ECDSA
static esp_err_t sign_hash_secp256k1(const uint8_t priv_key[WALLET_PRIVKEY_SIZE],
                                     const uint8_t hash[WALLET_HASH_SIZE],
                                     uint8_t sig_out[WALLET_SIG_SIZE]) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d, r, s;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1);
    if (ret == 0) ret = mbedtls_mpi_read_binary(&d, priv_key, WALLET_PRIVKEY_SIZE);

    wallet_trng_enable();
    if (ret == 0) {
        ret = mbedtls_ecdsa_sign_det_ext(&grp, &r, &s, &d,
                                         hash, WALLET_HASH_SIZE, MBEDTLS_MD_SHA256,
                                         wallet_trng_mbedtls_cb, NULL);
    }
    wallet_trng_disable();

    if (ret == 0) {
        ret = mbedtls_mpi_write_binary(&r, &sig_out[0], 32);
        ret |= mbedtls_mpi_write_binary(&s, &sig_out[32], 32);
    }

    mbedtls_mpi_free(&d);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    mbedtls_ecp_group_free(&grp);
    return (ret == 0) ? ESP_OK : ESP_FAIL;
}

// Szyfrowanie i zapis kluczy w NVS
esp_err_t wallet_vault_import_keys(const uint8_t priv_key[WALLET_PRIVKEY_SIZE],
                                   const uint8_t pub_key[WALLET_PUBKEY_SIZE],
                                   const char *password) {
    vault_blob_t blob;
    vault_plain_t plain;
    uint8_t kek[32];

    memcpy(plain.priv_key, priv_key, WALLET_PRIVKEY_SIZE);
    memcpy(plain.pub_key, pub_key, WALLET_PUBKEY_SIZE);

    wallet_trng_enable();
    wallet_trng_fill(blob.iv, IV_SIZE);
    wallet_trng_fill(blob.salt, SALT_SIZE);
    wallet_trng_disable();

    if (derive_hardware_kek(password, blob.salt, kek) != ESP_OK) {
        mbedtls_platform_zeroize(&plain, sizeof(plain));
        mbedtls_platform_zeroize(&blob, sizeof(blob));
        return ESP_FAIL;
    }

    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, kek, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_crypt_and_tag(&gcm, MBEDTLS_GCM_ENCRYPT, sizeof(plain),
                                        blob.iv, IV_SIZE, NULL, 0,
                                        (const uint8_t *)&plain, blob.ciphertext,
                                        TAG_SIZE, blob.tag);
    }
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(kek, sizeof(kek));
    mbedtls_platform_zeroize(&plain, sizeof(plain));
    if (ret != 0) {
        mbedtls_platform_zeroize(&blob, sizeof(blob));
        return ESP_FAIL;
    }

    nvs_handle_t nvs;
    esp_err_t err = nvs_open("wallet", NVS_READWRITE, &nvs);
    if (err == ESP_OK) {
        err = nvs_set_blob(nvs, "vault", &blob, sizeof(blob));
        if (err == ESP_OK) err = nvs_set_blob(nvs, "address", pub_key, WALLET_PUBKEY_SIZE);
        nvs_set_u32(nvs, "nonce", 0);
        if (err == ESP_OK) err = nvs_commit(nvs);
        nvs_close(nvs);
    }
    mbedtls_platform_zeroize(&blob, sizeof(blob));
    return err;
}

// Odczyt publicznego adresu portfela bez hasla
esp_err_t wallet_vault_get_address(uint8_t out_address[WALLET_PUBKEY_SIZE]) {
    if (!out_address) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t nvs;
    if (nvs_open("wallet", NVS_READONLY, &nvs) != ESP_OK) {
        return ESP_ERR_NOT_FOUND;
    }

    size_t size = WALLET_PUBKEY_SIZE;
    esp_err_t err = nvs_get_blob(nvs, "address", out_address, &size);
    nvs_close(nvs);

    return (err == ESP_OK && size == WALLET_PUBKEY_SIZE) ? ESP_OK : ESP_ERR_NOT_FOUND;
}

// Utworzenie nowego portfela i zapis kluczy
esp_err_t wallet_vault_generate_wallet(const char *password,
                                       char out_mnemonic[WALLET_MNEMONIC_MAX_LEN],
                                       uint8_t out_pub_key[WALLET_PUBKEY_SIZE]) {
    if (!password || strlen(password) == 0 || !out_mnemonic || !out_pub_key) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = wallet_bip39_generate_mnemonic(out_mnemonic, WALLET_MNEMONIC_MAX_LEN);
    if (err != ESP_OK) return err;

    uint8_t priv[WALLET_PRIVKEY_SIZE] = {0};
    err = wallet_bip39_mnemonic_to_private_key(out_mnemonic, priv);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(out_mnemonic, WALLET_MNEMONIC_MAX_LEN);
        mbedtls_platform_zeroize(priv, sizeof(priv));
        return err;
    }

    err = derive_pubkey_secp256k1(priv, out_pub_key);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(priv, sizeof(priv));
        mbedtls_platform_zeroize(out_mnemonic, WALLET_MNEMONIC_MAX_LEN);
        return err;
    }

    err = wallet_vault_import_keys(priv, out_pub_key, password);
    mbedtls_platform_zeroize(priv, sizeof(priv));

    if (err != ESP_OK) {
        mbedtls_platform_zeroize(out_mnemonic, WALLET_MNEMONIC_MAX_LEN);
        mbedtls_platform_zeroize(out_pub_key, WALLET_PUBKEY_SIZE);
        return err;
    }

    return ESP_OK;
}

// Odzyskanie portfela ze slow i zapis
esp_err_t wallet_vault_recover_wallet(const char *mnemonic,
                                      const char *password,
                                      uint8_t out_pub_key[WALLET_PUBKEY_SIZE]) {
    if (!mnemonic || !password || strlen(password) == 0 || !out_pub_key) {
        return ESP_ERR_INVALID_ARG;
    }

    uint8_t priv[WALLET_PRIVKEY_SIZE] = {0};
    esp_err_t err = wallet_bip39_mnemonic_to_private_key(mnemonic, priv);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(priv, sizeof(priv));
        return err;
    }

    err = derive_pubkey_secp256k1(priv, out_pub_key);
    if (err != ESP_OK) {
        mbedtls_platform_zeroize(priv, sizeof(priv));
        mbedtls_platform_zeroize(out_pub_key, WALLET_PUBKEY_SIZE);
        return err;
    }

    err = wallet_vault_import_keys(priv, out_pub_key, password);
    mbedtls_platform_zeroize(priv, sizeof(priv));

    if (err != ESP_OK) {
        mbedtls_platform_zeroize(out_pub_key, WALLET_PUBKEY_SIZE);
    }

    return err;
}

// Budowa i podpisanie transakcji w locie
esp_err_t wallet_vault_create_signed_tx(uint64_t amount,
                                        const uint8_t recipient_pub[WALLET_PUBKEY_SIZE],
                                        const char *password,
                                        wallet_transaction_t *out_tx) {
    if (!recipient_pub || !password || !out_tx) {
        return ESP_ERR_INVALID_ARG;
    }

    vault_blob_t blob;
    size_t sz = sizeof(blob);

    nvs_handle_t nvs;
    if (nvs_open("wallet", NVS_READWRITE, &nvs) != ESP_OK) {
        return ESP_ERR_NOT_FOUND;
    }

    esp_err_t err = nvs_get_blob(nvs, "vault", &blob, &sz);
    if (err != ESP_OK || sz != sizeof(blob)) {
        nvs_close(nvs);
        return ESP_ERR_NOT_FOUND;
    }

    uint8_t kek[32];
    if (derive_hardware_kek(password, blob.salt, kek) != ESP_OK) {
        nvs_close(nvs);
        mbedtls_platform_zeroize(&blob, sizeof(blob));
        return ESP_FAIL;
    }

    vault_plain_t plain;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);
    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, kek, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&gcm, sizeof(plain),
                                       blob.iv, IV_SIZE, NULL, 0,
                                       blob.tag, TAG_SIZE,
                                       blob.ciphertext, (uint8_t *)&plain);
    }
    mbedtls_gcm_free(&gcm);
    mbedtls_platform_zeroize(kek, sizeof(kek));
    mbedtls_platform_zeroize(&blob, sizeof(blob));

    if (ret != 0) {
        nvs_close(nvs);
        mbedtls_platform_zeroize(&plain, sizeof(plain));
        return ESP_ERR_INVALID_CRC;
    }

    uint32_t nonce = 0;
    nvs_get_u32(nvs, "nonce", &nonce);
    nonce++;
    nvs_set_u32(nvs, "nonce", nonce);
    nvs_commit(nvs);
    nvs_close(nvs);

    memset(out_tx, 0, sizeof(wallet_transaction_t));
    out_tx->type = KRST_TX_TRANSFER;
    out_tx->nonce = nonce;
    memcpy(out_tx->sender, plain.pub_key, WALLET_PUBKEY_SIZE);
    memcpy(out_tx->recipient, recipient_pub, WALLET_PUBKEY_SIZE);
    out_tx->amount = amount;

    uint8_t signing_hash[WALLET_HASH_SIZE];
    krst_tx_signing_hash(out_tx, signing_hash);

    esp_err_t sign_err = sign_hash_secp256k1(plain.priv_key, signing_hash, out_tx->signature);
    mbedtls_platform_zeroize(&plain, sizeof(plain));

    return sign_err;
}