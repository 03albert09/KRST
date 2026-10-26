
#include "node_crypto.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "esp_random.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ecdh.h"

static const char *TAG = "NODE_CRYPTO";
static mbedtls_ecdsa_context s_ecdsa_ctx;
static uint8_t s_my_pubkey[33];

// Sprzętowe generowanie losowych bajtów dla mbedTLS
static int esp_rng_wrapper(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

// Inicjalizacja tożsamości węzła ECDSA z NVS
void node_crypto_init(void) {
    mbedtls_ecdsa_init(&s_ecdsa_ctx);
    mbedtls_ecp_group_load(&s_ecdsa_ctx.grp, MBEDTLS_ECP_DP_SECP256K1);

    nvs_handle_t nvs_handle;
    ESP_ERROR_CHECK(nvs_open("storage", NVS_READWRITE, &nvs_handle));

    uint8_t priv_key[32];
    size_t priv_len = sizeof(priv_key);
    size_t pub_len = sizeof(s_my_pubkey);

    // Próba odczytu zapisanej pary kluczy z NVS
    if (nvs_get_blob(nvs_handle, "node_priv", priv_key, &priv_len) == ESP_OK && priv_len == 32 &&
        nvs_get_blob(nvs_handle, "node_pub", s_my_pubkey, &pub_len) == ESP_OK && pub_len == 33) {

        mbedtls_mpi_read_binary(&s_ecdsa_ctx.d, priv_key, 32);
        mbedtls_ecp_point_read_binary(&s_ecdsa_ctx.grp, &s_ecdsa_ctx.Q, s_my_pubkey, 33);
        ESP_LOGI(TAG, "Wczytano tozsamosc z NVS.");
    } else {
        ESP_LOGI(TAG, "Brak kluczy w NVS. Generowanie nowej tozsamosci ...");
        mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256K1, &s_ecdsa_ctx, esp_rng_wrapper, NULL);

        mbedtls_mpi_write_binary(&s_ecdsa_ctx.d, priv_key, 32);
        size_t olen = 0;
        mbedtls_ecp_point_write_binary(&s_ecdsa_ctx.grp, &s_ecdsa_ctx.Q,
                                       MBEDTLS_ECP_PF_COMPRESSED, &olen,
                                       s_my_pubkey, 33);

        nvs_set_blob(nvs_handle, "node_priv", priv_key, 32);
        nvs_set_blob(nvs_handle, "node_pub", s_my_pubkey, 33);
        nvs_commit(nvs_handle);
        ESP_LOGI(TAG, "Zapisano nowa tozsamosc do NVS.");
    }
    nvs_close(nvs_handle);

    char hex_id[68];
    node_crypto_bin_to_hex(s_my_pubkey, 33, hex_id, sizeof(hex_id));
    ESP_LOGI(TAG, "Tozsamosc wezla Node ID: %s", hex_id);
}

// Eksport 33-bajtowego klucza publicznego węzła
bool node_crypto_get_pubkey(uint8_t out_pubkey[33]) {
    memcpy(out_pubkey, s_my_pubkey, 33);
    return true;
}

// Podpisanie skrótu kluczem prywatnym ECDSA
bool node_crypto_sign(const uint8_t hash[32], uint8_t out_sig[64]) {
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecdsa_sign(&s_ecdsa_ctx.grp, &r, &s, &s_ecdsa_ctx.d,
                                 hash, 32, esp_rng_wrapper, NULL);
    if (ret == 0) {
        mbedtls_mpi_write_binary(&r, out_sig, 32);
        mbedtls_mpi_write_binary(&s, out_sig + 32, 32);
    } else {
        ESP_LOGE(TAG, "Blad podpisywania ECDSA (ret=-0x%04X)", -ret);
    }

    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return (ret == 0);
}

// Weryfikacja podpisu kryptograficznego ECDSA dla skrótu
bool node_crypto_verify(const uint8_t pubkey[33], const uint8_t hash[32], const uint8_t sig[64]) {
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);

    int ret = mbedtls_ecp_point_read_binary(&s_ecdsa_ctx.grp, &Q, pubkey, 33);
    if (ret == 0) {
        mbedtls_mpi_read_binary(&r, sig, 32);
        mbedtls_mpi_read_binary(&s, sig + 32, 32);
        ret = mbedtls_ecdsa_verify(&s_ecdsa_ctx.grp, hash, 32, &Q, &r, &s);
    }

    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return (ret == 0);
}

// Obliczenie skrótu sesji handshake (Transcript)
void node_crypto_compute_handshake_hash(const uint8_t chal_a[32], const uint8_t chal_b[32],
                                        const uint8_t pk_a[33], const uint8_t pk_b[33],
                                        uint8_t out_hash[32]) {
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, (const uint8_t *)"P2P-MITM-V1", 11);
    mbedtls_sha256_update(&sha, chal_a, 32);
    mbedtls_sha256_update(&sha, chal_b, 32);
    mbedtls_sha256_update(&sha, pk_a, 33);
    mbedtls_sha256_update(&sha, pk_b, 33);
    mbedtls_sha256_finish(&sha, out_hash);
    mbedtls_sha256_free(&sha);
}

// Obliczenie wspólnego sekretu Diffie-Hellman ECDH
bool node_crypto_compute_shared_secret(const uint8_t peer_pubkey[33], uint8_t out_secret[32]) {
    mbedtls_ecp_point Q;
    mbedtls_ecp_point_init(&Q);
    mbedtls_mpi z;
    mbedtls_mpi_init(&z);

    int ret = mbedtls_ecp_point_read_binary(&s_ecdsa_ctx.grp, &Q, peer_pubkey, 33);
    if (ret == 0) {
        ret = mbedtls_ecdh_compute_shared(&s_ecdsa_ctx.grp, &z, &Q, &s_ecdsa_ctx.d,
                                          esp_rng_wrapper, NULL);
        if (ret == 0) {
            mbedtls_mpi_write_binary(&z, out_secret, 32);
        }
    }

    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&z);
    return (ret == 0);
}

// Wyprowadzenie symetrycznego klucza sesji KDF
void node_crypto_derive_session_key(const uint8_t shared_secret[32],
                                    const uint8_t chal_a[32],
                                    const uint8_t chal_b[32],
                                    uint8_t out_session_key[32]) {
    mbedtls_sha256_context sha;
    mbedtls_sha256_init(&sha);
    mbedtls_sha256_starts(&sha, 0);
    mbedtls_sha256_update(&sha, (const uint8_t *)"P2P-SESSION-KEY-V1", 18);
    mbedtls_sha256_update(&sha, shared_secret, 32);
    mbedtls_sha256_update(&sha, chal_a, 32);
    mbedtls_sha256_update(&sha, chal_b, 32);
    mbedtls_sha256_finish(&sha, out_session_key);
    mbedtls_sha256_free(&sha);
}

// Obliczenie 16-bajtowego HMAC-SHA256 dla ramki
void node_crypto_calc_msg_hmac(const uint8_t session_key[32],
                               uint16_t magic, uint16_t cmd, uint32_t length, uint32_t seq,
                               const void *payload, uint32_t payload_len,
                               uint8_t out_hmac[16]) {
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    memset(k_ipad, 0x36, 64);
    memset(k_opad, 0x5c, 64);

    for (int i = 0; i < 32; i++) {
        k_ipad[i] ^= session_key[i];
        k_opad[i] ^= session_key[i];
    }

    uint8_t inner_hash[32];
    mbedtls_sha256_context ctx;

    struct __attribute__((packed)) {
        uint16_t magic;
        uint16_t cmd;
        uint32_t length;
        uint32_t seq;
    } hdr = { magic, cmd, length, seq };

    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, k_ipad, 64);
    mbedtls_sha256_update(&ctx, (const uint8_t *)&hdr, sizeof(hdr));
    if (payload != NULL && payload_len > 0) {
        mbedtls_sha256_update(&ctx, (const uint8_t *)payload, payload_len);
    }
    mbedtls_sha256_finish(&ctx, inner_hash);

    uint8_t full_hmac[32];
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, k_opad, 64);
    mbedtls_sha256_update(&ctx, inner_hash, 32);
    mbedtls_sha256_finish(&ctx, full_hmac);
    mbedtls_sha256_free(&ctx);

    memcpy(out_hmac, full_hmac, 16);
}

// Weryfikacja HMAC w stałym czasie (constant-time)
bool node_crypto_verify_msg_hmac(const uint8_t session_key[32],
                                 uint16_t magic, uint16_t cmd, uint32_t length, uint32_t seq,
                                 const void *payload, uint32_t payload_len,
                                 const uint8_t expected_hmac[16]) {
    uint8_t computed[16];
    node_crypto_calc_msg_hmac(session_key, magic, cmd, length, seq, payload, payload_len, computed);

    uint8_t diff = 0;
    for (int i = 0; i < 16; i++) {
        diff |= (computed[i] ^ expected_hmac[i]);
    }
    return (diff == 0);
}

// Konwersja danych binarnych na format szesnastkowy
void node_crypto_bin_to_hex(const uint8_t *data, size_t data_len, char *out_hex, size_t max_len) {
    if (!data || !out_hex || max_len < 1) return;
    static const char hex_chars[] = "0123456789abcdef";
    size_t written = 0;
    for (size_t i = 0; i < data_len && (written + 2) < max_len; i++) {
        out_hex[written++] = hex_chars[(data[i] >> 4) & 0x0F];
        out_hex[written++] = hex_chars[data[i] & 0x0F];
    }
    out_hex[written] = '\0';
}
