#include <stdlib.h>
#include <string.h>
#include "unity.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "node_crypto.h"
#include "p2p_protocol.h"
#include "test_vectors.h"

#define TEST_CONN_ID 42

// Para polaczonych gniazd TCP na interfejsie loopback
static void tcp_pair(int *out_client, int *out_server) {
    int listener = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    TEST_ASSERT_GREATER_OR_EQUAL(0, listener);

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = 0,
        .sin_addr.s_addr = htonl(INADDR_LOOPBACK),
    };
    TEST_ASSERT_EQUAL(0, bind(listener, (struct sockaddr *)&addr, sizeof(addr)));
    TEST_ASSERT_EQUAL(0, listen(listener, 1));

    socklen_t addr_len = sizeof(addr);
    TEST_ASSERT_EQUAL(0, getsockname(listener, (struct sockaddr *)&addr, &addr_len));

    int client = socket(AF_INET, SOCK_STREAM, IPPROTO_IP);
    TEST_ASSERT_GREATER_OR_EQUAL(0, client);
    TEST_ASSERT_EQUAL(0, connect(client, (struct sockaddr *)&addr, sizeof(addr)));

    int server = accept(listener, NULL, NULL);
    TEST_ASSERT_GREATER_OR_EQUAL(0, server);
    close(listener);

    p2p_socket_set_timeout(client, 1);
    p2p_socket_set_timeout(server, 1);
    *out_client = client;
    *out_server = server;
}

// Wypelnia naglowek ramki przykladowymi wartosciami
static void make_header(p2p_header_t *hdr) {
    memset(hdr, 0, sizeof(*hdr));
    hdr->magic = MAGIC_BYTES;
    hdr->cmd = CMD_PING;
    hdr->seq = 0x01020304;
    memset(hdr->hmac, 0x5C, sizeof(hdr->hmac));
}

typedef struct {
    int sock;
    const uint8_t *data;
    size_t len;
    SemaphoreHandle_t done;
} delayed_send_t;

// Wysyla dane z opoznieniem, zeby wymusic osobne segmenty TCP
static void delayed_send_task(void *arg) {
    delayed_send_t *job = (delayed_send_t *)arg;
    vTaskDelay(pdMS_TO_TICKS(100));
    send(job->sock, job->data, job->len, 0);
    xSemaphoreGive(job->done);
    vTaskDelete(NULL);
}

TEST_CASE("naglowek w jednym kawalku jest odczytany", "[p2p_frame]") {
    int client, server;
    tcp_pair(&client, &server);

    p2p_header_t sent, received;
    make_header(&sent);
    TEST_ASSERT_EQUAL(sizeof(sent), send(client, &sent, sizeof(sent), 0));

    TEST_ASSERT_EQUAL(P2P_RECV_OK, p2p_recv_header(server, &received));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(&sent, &received, sizeof(sent));

    close(client);
    close(server);
}

TEST_CASE("naglowek w dwoch kawalkach jest zlozony w calosc", "[p2p_frame]") {
    int client, server;
    tcp_pair(&client, &server);

    p2p_header_t sent, received;
    make_header(&sent);
    const size_t first_part = 5;
    TEST_ASSERT_EQUAL(first_part, send(client, &sent, first_part, 0));

    delayed_send_t job = {
        .sock = client,
        .data = (const uint8_t *)&sent + first_part,
        .len = sizeof(sent) - first_part,
        .done = xSemaphoreCreateBinary(),
    };
    TEST_ASSERT_NOT_NULL(job.done);
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreate(delayed_send_task, "delayed_send", 3072, &job, 5, NULL));

    TEST_ASSERT_EQUAL(P2P_RECV_OK, p2p_recv_header(server, &received));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(&sent, &received, sizeof(sent));

    xSemaphoreTake(job.done, portMAX_DELAY);
    vSemaphoreDelete(job.done);
    close(client);
    close(server);
}

TEST_CASE("brak danych jest stanem bezczynnosci, a nie bledem", "[p2p_frame]") {
    int client, server;
    tcp_pair(&client, &server);

    p2p_header_t received;
    TEST_ASSERT_EQUAL(P2P_RECV_IDLE, p2p_recv_header(server, &received));

    close(client);
    close(server);
}

TEST_CASE("zamkniecie polaczenia jest rozpoznane", "[p2p_frame]") {
    int client, server;
    tcp_pair(&client, &server);
    close(client);

    p2p_header_t received;
    TEST_ASSERT_EQUAL(P2P_RECV_CLOSED, p2p_recv_header(server, &received));

    close(server);
}

TEST_CASE("urwany naglowek jest bledem", "[p2p_frame]") {
    int client, server;
    tcp_pair(&client, &server);

    p2p_header_t sent, received;
    make_header(&sent);
    TEST_ASSERT_EQUAL(5, send(client, &sent, 5, 0));
    close(client);

    TEST_ASSERT_EQUAL(P2P_RECV_ERROR, p2p_recv_header(server, &received));

    close(server);
}

TEST_CASE("ramka przed uwierzytelnieniem ma zerowy seq i HMAC", "[p2p_channel]") {
    int client, server;
    tcp_pair(&client, &server);

    p2p_channel_t channel;
    TEST_ASSERT_TRUE(p2p_channel_create(&channel));
    p2p_channel_open(&channel, client, TEST_CONN_ID);

    TEST_ASSERT_TRUE(p2p_channel_send(&channel, TEST_CONN_ID, CMD_HELLO, TV_PAYLOAD, sizeof(TV_PAYLOAD)));

    p2p_header_t hdr;
    uint8_t zeros[sizeof(hdr.hmac)] = {0};
    uint8_t payload[sizeof(TV_PAYLOAD)];
    TEST_ASSERT_EQUAL(P2P_RECV_OK, p2p_recv_header(server, &hdr));
    TEST_ASSERT_EQUAL_HEX16(MAGIC_BYTES, hdr.magic);
    TEST_ASSERT_EQUAL_UINT16(CMD_HELLO, hdr.cmd);
    TEST_ASSERT_EQUAL_UINT32(sizeof(TV_PAYLOAD), hdr.length);
    TEST_ASSERT_EQUAL_UINT32(0, hdr.seq);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(zeros, hdr.hmac, sizeof(zeros));
    TEST_ASSERT_TRUE(p2p_recv_exact(server, payload, sizeof(payload)));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(TV_PAYLOAD, payload, sizeof(payload));

    p2p_channel_close(&channel);
    vSemaphoreDelete(channel.lock);
    close(server);
}

TEST_CASE("ramki sesji maja kolejne seq i poprawny HMAC", "[p2p_channel]") {
    int client, server;
    tcp_pair(&client, &server);

    p2p_channel_t channel;
    TEST_ASSERT_TRUE(p2p_channel_create(&channel));
    p2p_channel_open(&channel, client, TEST_CONN_ID);
    p2p_channel_set_session_key(&channel, TV_KEY);

    TEST_ASSERT_TRUE(p2p_channel_send(&channel, TEST_CONN_ID, CMD_PING, NULL, 0));
    TEST_ASSERT_TRUE(p2p_channel_send(&channel, TEST_CONN_ID, CMD_ADDR, TV_PAYLOAD, sizeof(TV_PAYLOAD)));

    p2p_header_t hdr;
    TEST_ASSERT_EQUAL(P2P_RECV_OK, p2p_recv_header(server, &hdr));
    TEST_ASSERT_EQUAL_UINT32(1, hdr.seq);
    TEST_ASSERT_TRUE(node_crypto_verify_msg_hmac(TV_KEY, hdr.magic, hdr.cmd, hdr.length, hdr.seq, NULL, 0, hdr.hmac));

    uint8_t payload[sizeof(TV_PAYLOAD)];
    TEST_ASSERT_EQUAL(P2P_RECV_OK, p2p_recv_header(server, &hdr));
    TEST_ASSERT_EQUAL_UINT32(2, hdr.seq);
    TEST_ASSERT_TRUE(p2p_recv_exact(server, payload, sizeof(payload)));
    TEST_ASSERT_TRUE(node_crypto_verify_msg_hmac(TV_KEY, hdr.magic, hdr.cmd, hdr.length, hdr.seq,
                                                 payload, sizeof(payload), hdr.hmac));

    p2p_channel_close(&channel);
    vSemaphoreDelete(channel.lock);
    close(server);
}

TEST_CASE("nieaktualny conn_id jest odrzucany", "[p2p_channel]") {
    int client, server;
    tcp_pair(&client, &server);

    p2p_channel_t channel;
    TEST_ASSERT_TRUE(p2p_channel_create(&channel));
    p2p_channel_open(&channel, client, TEST_CONN_ID + 1);

    TEST_ASSERT_FALSE(p2p_channel_send(&channel, TEST_CONN_ID, CMD_PING, NULL, 0));
    TEST_ASSERT_FALSE(p2p_channel_send(&channel, 0, CMD_PING, NULL, 0));
    TEST_ASSERT_FALSE(p2p_channel_is_broken(&channel));

    p2p_header_t hdr;
    TEST_ASSERT_EQUAL(P2P_RECV_IDLE, p2p_recv_header(server, &hdr));

    p2p_channel_close(&channel);
    TEST_ASSERT_FALSE(p2p_channel_send(&channel, TEST_CONN_ID + 1, CMD_PING, NULL, 0));

    vSemaphoreDelete(channel.lock);
    close(server);
}

TEST_CASE("nieudana wysylka uszkadza kanal i zamyka strumien", "[p2p_channel]") {
    int client, server;
    tcp_pair(&client, &server);

    p2p_channel_t channel;
    TEST_ASSERT_TRUE(p2p_channel_create(&channel));
    p2p_channel_open(&channel, client, TEST_CONN_ID);

    const size_t big_len = 32 * 1024;
    uint8_t *big = calloc(1, big_len);
    TEST_ASSERT_NOT_NULL(big);

    TEST_ASSERT_FALSE(p2p_channel_send(&channel, TEST_CONN_ID, CMD_ADDR, big, big_len));
    TEST_ASSERT_TRUE(p2p_channel_is_broken(&channel));
    TEST_ASSERT_FALSE(p2p_channel_send(&channel, TEST_CONN_ID, CMD_PING, NULL, 0));

    free(big);
    p2p_channel_close(&channel);
    TEST_ASSERT_FALSE(p2p_channel_is_broken(&channel));
    vSemaphoreDelete(channel.lock);
    close(server);
}

TEST_CASE("zerwanie polaczenia dziala tylko dla aktualnego conn_id", "[p2p_channel]") {
    int client, server;
    tcp_pair(&client, &server);

    p2p_channel_t channel;
    TEST_ASSERT_TRUE(p2p_channel_create(&channel));
    p2p_channel_open(&channel, client, TEST_CONN_ID);

    p2p_channel_abort(&channel, TEST_CONN_ID + 1);
    TEST_ASSERT_FALSE(p2p_channel_is_broken(&channel));

    p2p_channel_abort(&channel, TEST_CONN_ID);
    TEST_ASSERT_TRUE(p2p_channel_is_broken(&channel));
    TEST_ASSERT_FALSE(p2p_channel_send(&channel, TEST_CONN_ID, CMD_PING, NULL, 0));

    p2p_header_t hdr;
    TEST_ASSERT_EQUAL(P2P_RECV_CLOSED, p2p_recv_header(server, &hdr));

    p2p_channel_close(&channel);
    vSemaphoreDelete(channel.lock);
    close(server);
}

#define CONCURRENT_FRAMES_PER_TASK 50
#define CONCURRENT_PAYLOAD_LEN     300

typedef struct {
    p2p_channel_t *channel;
    uint8_t fill;
    bool ok;
    SemaphoreHandle_t done;
} concurrent_job_t;

// Wysyla serie ramek z jednego zadania, rownolegle z innymi
static void concurrent_send_task(void *arg) {
    concurrent_job_t *job = (concurrent_job_t *)arg;
    uint8_t payload[CONCURRENT_PAYLOAD_LEN];
    memset(payload, job->fill, sizeof(payload));

    job->ok = true;
    for (int i = 0; i < CONCURRENT_FRAMES_PER_TASK; i++) {
        if (!p2p_channel_send(job->channel, TEST_CONN_ID, CMD_ADDR, payload, sizeof(payload))) {
            job->ok = false;
            break;
        }
        if (i % 5 == 0) vTaskDelay(1);
    }
    xSemaphoreGive(job->done);
    vTaskDelete(NULL);
}

TEST_CASE("dwa zadania nadajace naraz nie psuja strumienia ani numeracji", "[p2p_channel]") {
    int client, server;
    tcp_pair(&client, &server);

    p2p_channel_t channel;
    TEST_ASSERT_TRUE(p2p_channel_create(&channel));
    p2p_channel_open(&channel, client, TEST_CONN_ID);
    p2p_channel_set_session_key(&channel, TV_KEY);

    concurrent_job_t jobs[2] = {
        { .channel = &channel, .fill = 0x11, .done = xSemaphoreCreateBinary() },
        { .channel = &channel, .fill = 0x22, .done = xSemaphoreCreateBinary() },
    };
    TEST_ASSERT_NOT_NULL(jobs[0].done);
    TEST_ASSERT_NOT_NULL(jobs[1].done);
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreate(concurrent_send_task, "send_a", 4096, &jobs[0], 3, NULL));
    TEST_ASSERT_EQUAL(pdPASS, xTaskCreate(concurrent_send_task, "send_b", 4096, &jobs[1], 3, NULL));

    static uint8_t payload[CONCURRENT_PAYLOAD_LEN];
    int count_a = 0;
    int count_b = 0;
    const int total = 2 * CONCURRENT_FRAMES_PER_TASK;

    for (int i = 0; i < total; i++) {
        p2p_header_t hdr;
        TEST_ASSERT_EQUAL(P2P_RECV_OK, p2p_recv_header(server, &hdr));
        TEST_ASSERT_EQUAL_HEX16(MAGIC_BYTES, hdr.magic);
        TEST_ASSERT_EQUAL_UINT32(CONCURRENT_PAYLOAD_LEN, hdr.length);
        TEST_ASSERT_EQUAL_UINT32(i + 1, hdr.seq);
        TEST_ASSERT_TRUE(p2p_recv_exact(server, payload, sizeof(payload)));
        TEST_ASSERT_TRUE(node_crypto_verify_msg_hmac(TV_KEY, hdr.magic, hdr.cmd, hdr.length, hdr.seq,
                                                     payload, sizeof(payload), hdr.hmac));

        for (size_t j = 1; j < sizeof(payload); j++) {
            TEST_ASSERT_EQUAL_HEX8(payload[0], payload[j]);
        }
        if (payload[0] == 0x11) count_a++;
        else if (payload[0] == 0x22) count_b++;
        else TEST_FAIL_MESSAGE("Nieznany wzor payloadu");
    }

    xSemaphoreTake(jobs[0].done, portMAX_DELAY);
    xSemaphoreTake(jobs[1].done, portMAX_DELAY);
    TEST_ASSERT_TRUE(jobs[0].ok);
    TEST_ASSERT_TRUE(jobs[1].ok);
    TEST_ASSERT_EQUAL(CONCURRENT_FRAMES_PER_TASK, count_a);
    TEST_ASSERT_EQUAL(CONCURRENT_FRAMES_PER_TASK, count_b);

    vSemaphoreDelete(jobs[0].done);
    vSemaphoreDelete(jobs[1].done);
    p2p_channel_close(&channel);
    vSemaphoreDelete(channel.lock);
    close(server);
}
