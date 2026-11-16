#include <string.h>
#include "unity.h"
#include "esp_random.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecp.h"
#include "node_crypto.h"
#include "test_vectors.h"

// Tozsamosc jest wczytywana z NVS raz na cale uruchomienie testow
static void ensure_identity_loaded(void) {
    static bool s_loaded = false;
    if (!s_loaded) {
        node_crypto_init();
        s_loaded = true;
    }
}

// Generator losowosci dla mbedTLS w testach
static int test_rng(void *ctx, unsigned char *buf, size_t len) {
    (void)ctx;
    esp_fill_random(buf, len);
    return 0;
}

TEST_CASE("HMAC ramki z payloadem zgadza sie z wektorem", "[crypto]") {
    uint8_t out[16];
    node_crypto_calc_msg_hmac(TV_KEY, 0xF1B9, 8, sizeof(TV_PAYLOAD), 7, TV_PAYLOAD, sizeof(TV_PAYLOAD), out);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TV_HMAC_WITH_PAYLOAD, out, 16);
}

TEST_CASE("HMAC ramki bez payloadu zgadza sie z wektorem", "[crypto]") {
    uint8_t out[16];
    node_crypto_calc_msg_hmac(TV_KEY, 0xF1B9, 9, 0, 1, NULL, 0, out);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TV_HMAC_NO_PAYLOAD, out, 16);
}

TEST_CASE("weryfikacja HMAC odrzuca kazda zmiane ramki", "[crypto]") {
    const uint32_t len = sizeof(TV_PAYLOAD);
    TEST_ASSERT_TRUE(node_crypto_verify_msg_hmac(TV_KEY, 0xF1B9, 8, len, 7, TV_PAYLOAD, len, TV_HMAC_WITH_PAYLOAD));

    TEST_ASSERT_FALSE(node_crypto_verify_msg_hmac(TV_KEY, 0xF1B9, 8, len, 8, TV_PAYLOAD, len, TV_HMAC_WITH_PAYLOAD));
    TEST_ASSERT_FALSE(node_crypto_verify_msg_hmac(TV_KEY, 0xF1B9, 9, len, 7, TV_PAYLOAD, len, TV_HMAC_WITH_PAYLOAD));

    uint8_t tampered[sizeof(TV_PAYLOAD)];
    memcpy(tampered, TV_PAYLOAD, len);
    tampered[0] ^= 0x01;
    TEST_ASSERT_FALSE(node_crypto_verify_msg_hmac(TV_KEY, 0xF1B9, 8, len, 7, tampered, len, TV_HMAC_WITH_PAYLOAD));

    uint8_t other_key[32];
    memcpy(other_key, TV_KEY, 32);
    other_key[31] ^= 0x80;
    TEST_ASSERT_FALSE(node_crypto_verify_msg_hmac(other_key, 0xF1B9, 8, len, 7, TV_PAYLOAD, len, TV_HMAC_WITH_PAYLOAD));
}

TEST_CASE("skrot handshake zgadza sie z wektorem", "[crypto]") {
    uint8_t out[32];
    node_crypto_compute_handshake_hash(TV_CHAL_A, TV_CHAL_B, TV_PK_A, TV_PK_B, out);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TV_HANDSHAKE_HASH, out, 32);
}

TEST_CASE("klucz sesji zgadza sie z wektorem", "[crypto]") {
    uint8_t out[32];
    node_crypto_derive_session_key(TV_SHARED, TV_CHAL_A, TV_CHAL_B, out);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TV_SESSION_KEY, out, 32);
}

TEST_CASE("podpis wezla przechodzi weryfikacje tylko dla tych samych danych", "[crypto]") {
    ensure_identity_loaded();

    uint8_t pubkey[33];
    uint8_t signature[64];
    uint8_t hash[32];
    esp_fill_random(hash, sizeof(hash));

    TEST_ASSERT_TRUE(node_crypto_get_pubkey(pubkey));
    TEST_ASSERT_TRUE(node_crypto_sign(hash, signature));
    TEST_ASSERT_TRUE(node_crypto_verify(pubkey, hash, signature));

    hash[0] ^= 0x01;
    TEST_ASSERT_FALSE(node_crypto_verify(pubkey, hash, signature));
    TEST_ASSERT_FALSE(node_crypto_verify(TV_ECDSA_PUBKEY, TV_ECDSA_HASH, signature));
}

TEST_CASE("weryfikacja przyjmuje podpis z zewnetrznej biblioteki", "[crypto]") {
    ensure_identity_loaded();

    TEST_ASSERT_TRUE(node_crypto_verify(TV_ECDSA_PUBKEY, TV_ECDSA_HASH, TV_ECDSA_SIGNATURE));

    uint8_t tampered[64];
    memcpy(tampered, TV_ECDSA_SIGNATURE, sizeof(tampered));
    tampered[63] ^= 0x01;
    TEST_ASSERT_FALSE(node_crypto_verify(TV_ECDSA_PUBKEY, TV_ECDSA_HASH, tampered));
}

TEST_CASE("ECDH daje ten sam sekret po obu stronach", "[crypto]") {
    ensure_identity_loaded();

    mbedtls_ecp_group grp;
    mbedtls_ecp_point other_q, node_q;
    mbedtls_mpi other_d, z;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&other_q);
    mbedtls_ecp_point_init(&node_q);
    mbedtls_mpi_init(&other_d);
    mbedtls_mpi_init(&z);

    TEST_ASSERT_EQUAL(0, mbedtls_ecp_group_load(&grp, MBEDTLS_ECP_DP_SECP256K1));
    TEST_ASSERT_EQUAL(0, mbedtls_ecp_gen_keypair(&grp, &other_d, &other_q, test_rng, NULL));

    uint8_t other_pubkey[33];
    size_t other_len = 0;
    TEST_ASSERT_EQUAL(0, mbedtls_ecp_point_write_binary(&grp, &other_q, MBEDTLS_ECP_PF_COMPRESSED,
                                                        &other_len, other_pubkey, sizeof(other_pubkey)));

    uint8_t node_pubkey[33];
    TEST_ASSERT_TRUE(node_crypto_get_pubkey(node_pubkey));
    TEST_ASSERT_EQUAL(0, mbedtls_ecp_point_read_binary(&grp, &node_q, node_pubkey, sizeof(node_pubkey)));
    TEST_ASSERT_EQUAL(0, mbedtls_ecdh_compute_shared(&grp, &z, &node_q, &other_d, test_rng, NULL));

    uint8_t expected[32];
    uint8_t secret[32];
    TEST_ASSERT_EQUAL(0, mbedtls_mpi_write_binary(&z, expected, sizeof(expected)));
    TEST_ASSERT_TRUE(node_crypto_compute_shared_secret(other_pubkey, secret));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(expected, secret, 32);

    mbedtls_ecp_group_free(&grp);
    mbedtls_ecp_point_free(&other_q);
    mbedtls_ecp_point_free(&node_q);
    mbedtls_mpi_free(&other_d);
    mbedtls_mpi_free(&z);
}

TEST_CASE("ECDH odrzuca klucz o blednym formacie", "[crypto]") {
    ensure_identity_loaded();

    uint8_t bad_pubkey[33];
    memset(bad_pubkey, 0x11, sizeof(bad_pubkey));
    bad_pubkey[0] = 0x05;

    uint8_t secret[32];
    TEST_ASSERT_FALSE(node_crypto_compute_shared_secret(bad_pubkey, secret));
}

TEST_CASE("kontrola klucza wymaga punktu na krzywej", "[crypto]") {
    ensure_identity_loaded();

    uint8_t node_pubkey[33];
    TEST_ASSERT_TRUE(node_crypto_get_pubkey(node_pubkey));
    TEST_ASSERT_TRUE(node_crypto_is_valid_pubkey(node_pubkey));
    TEST_ASSERT_TRUE(node_crypto_is_valid_pubkey(TV_ECDSA_PUBKEY));

    TEST_ASSERT_FALSE(node_crypto_is_valid_pubkey(TV_OFF_CURVE_PUBKEY));

    uint8_t bad_prefix[33];
    memcpy(bad_prefix, TV_ECDSA_PUBKEY, sizeof(bad_prefix));
    bad_prefix[0] = 0x05;
    TEST_ASSERT_FALSE(node_crypto_is_valid_pubkey(bad_prefix));
}

TEST_CASE("konwersja na hex respektuje rozmiar bufora", "[crypto]") {
    const uint8_t data[] = { 0x00, 0xAB, 0xFF };

    char full[7];
    node_crypto_bin_to_hex(data, sizeof(data), full, sizeof(full));
    TEST_ASSERT_EQUAL_STRING("00abff", full);

    char short_buf[4];
    node_crypto_bin_to_hex(data, sizeof(data), short_buf, sizeof(short_buf));
    TEST_ASSERT_EQUAL_STRING("00", short_buf);
}
