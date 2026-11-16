#include <stdlib.h>
#include <string.h>
#include "unity.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "chain_net.h"
#include "consensus.h"
#include "ledger.h"
#include "chain_test_helpers.h"

#define NOW 1800000000u
#define MAX_FRAMES 40
#define MAX_FRAME_DATA sizeof(chain_net_get_blocks_t)

typedef enum { FRAME_SEND, FRAME_BROADCAST } frame_kind_t;

typedef struct {
    frame_kind_t kind;
    p2p_peer_ref_t peer;
    bool has_exclude;
    uint16_t cmd;
    uint32_t length;
    uint8_t data[MAX_FRAME_DATA];
} recorded_frame_t;

static recorded_frame_t *s_frames = NULL;
static int s_frame_count;
static p2p_peer_ref_t s_disconnected;
static int s_disconnect_count;
static volatile bool s_record_failed;

static const p2p_peer_ref_t PEER_A = { .slot = 0, .conn_id = 101 };
static const p2p_peer_ref_t PEER_B = { .slot = 1, .conn_id = 202 };

static block_t s_block;

// Zapisuje ramke wyslana przez chain_net. Dziala w zadaniu lancucha, wiec bledy sprawdza dopiero deliver().
static void record(frame_kind_t kind, p2p_peer_ref_t peer, bool has_exclude, uint16_t cmd,
                   const void *payload, uint32_t length) {
    if (s_frame_count >= MAX_FRAMES || length > MAX_FRAME_DATA) {
        s_record_failed = true;
        return;
    }

    recorded_frame_t *frame = &s_frames[s_frame_count++];
    frame->kind = kind;
    frame->peer = peer;
    frame->has_exclude = has_exclude;
    frame->cmd = cmd;
    frame->length = length;
    if (length > 0) {
        memcpy(frame->data, payload, length);
    }
}

// Zastepczy transport: zapis ramki wyslanej do jednego wezla
static bool fake_send(p2p_peer_ref_t peer, p2p_cmd_t cmd, const void *payload, uint32_t length) {
    record(FRAME_SEND, peer, false, (uint16_t)cmd, payload, length);
    return true;
}

// Zastepczy transport: zapis ramki rozeslanej do wszystkich wezlow
static int fake_broadcast(p2p_cmd_t cmd, const void *payload, uint32_t length, const p2p_peer_ref_t *exclude) {
    p2p_peer_ref_t none = { .slot = -1, .conn_id = 0 };
    record(FRAME_BROADCAST, exclude ? *exclude : none, exclude != NULL, (uint16_t)cmd, payload, length);
    return 1;
}

// Zastepczy transport: zapis rozlaczenia wezla
static void fake_disconnect(p2p_peer_ref_t peer) {
    s_disconnected = peer;
    s_disconnect_count++;
}

// Czysci zapisane ramki i rozlaczenia
static void clear_frames(void) {
    s_frame_count = 0;
    s_disconnect_count = 0;
    s_record_failed = false;
}

// Przygotowuje swiezy lancuch, zadanie lancucha i chain_net z zastepczym transportem
static void prepare(void) {
    if (s_frames == NULL) {
        s_frames = malloc(MAX_FRAMES * sizeof(recorded_frame_t));
        TEST_ASSERT_NOT_NULL(s_frames);
    }

    th_prepare_chain_task();
    th_set_result_forward(chain_net_on_block_result);

    chain_net_transport_t transport = {
        .send = fake_send,
        .broadcast = fake_broadcast,
        .disconnect = fake_disconnect,
    };
    chain_net_init(&transport);
    clear_frames();
}

// Dopisuje podana liczbe blokow bezposrednio do lancucha, bez kolejki
static void grow_chain(int blocks) {
    for (int i = 0; i < blocks; i++) {
        chain_tip_t tip;
        chain_get_tip(&tip);
        th_make_child(&s_block, tip.hash, tip.height, tip.timestamp, 0);
        TEST_ASSERT_EQUAL(CHAIN_ACCEPTED_TIP, chain_accept_block(&s_block, NOW, false, NULL));
    }
}

// Tworzy dziecko aktualnego tipa
static void make_tip_child(block_t *block) {
    chain_tip_t tip;
    chain_get_tip(&tip);
    th_make_child(block, tip.hash, tip.height, tip.timestamp, 0);
}

// Przekazuje wiadomosc do chain_net i czeka, az zadanie lancucha ja przetworzy
static void deliver(p2p_peer_ref_t peer, p2p_cmd_t cmd, const void *payload, uint32_t length) {
    TEST_ASSERT_TRUE(chain_net_handle_message(peer, (uint16_t)cmd, (const uint8_t *)payload, length));
    th_wait_chain_idle();
    TEST_ASSERT_FALSE(s_record_failed);
}

// Przekazuje blok jako wiadomosc podanego typu
static void deliver_block(p2p_peer_ref_t peer, p2p_cmd_t cmd, const block_t *block) {
    deliver(peer, cmd, block, (uint32_t)block_serialized_size(block));
}

// Buduje wiadomosc o stanie lancucha z podana praca
static chain_net_status_t make_status(uint64_t work) {
    chain_net_status_t status;
    memset(&status, 0, sizeof(status));
    chain_get_network_id(status.network_id);
    status.cumulative_work = work;
    return status;
}

// Dlugosc prosby o bloki z podana liczba hashy lokatora
static uint32_t locator_length(uint16_t count) {
    return offsetof(chain_net_get_blocks_t, hashes) + (uint32_t)count * KRST_HASH_SIZE;
}

// Wysokosc bloku zapisanego w ramce
static uint32_t frame_block_height(const recorded_frame_t *frame) {
    return ((const block_t *)frame->data)->header.height;
}

TEST_CASE("po handshake wezel wysyla stan swojego lancucha", "[chain_net]") {
    prepare();
    grow_chain(2);

    chain_net_on_peer_authenticated(PEER_A);

    TEST_ASSERT_EQUAL(1, s_frame_count);
    TEST_ASSERT_EQUAL(FRAME_SEND, s_frames[0].kind);
    TEST_ASSERT_EQUAL_UINT16(CMD_CHAIN_STATUS, s_frames[0].cmd);
    TEST_ASSERT_EQUAL_UINT32(sizeof(chain_net_status_t), s_frames[0].length);

    const chain_net_status_t *status = (const chain_net_status_t *)s_frames[0].data;
    chain_tip_t tip;
    uint8_t network_id[KRST_HASH_SIZE];
    chain_get_tip(&tip);
    chain_get_network_id(network_id);

    TEST_ASSERT_EQUAL_HEX8_ARRAY(network_id, status->network_id, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tip.hash, status->tip_hash, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_UINT32(2, status->height);
    TEST_ASSERT_EQUAL_UINT64(tip.cumulative_work, status->cumulative_work);
}

TEST_CASE("wezel z innej sieci jest rozlaczany", "[chain_net]") {
    prepare();

    chain_net_status_t status = make_status(1);
    status.network_id[0] ^= 0xFF;
    TEST_ASSERT_FALSE(chain_net_handle_message(PEER_A, CMD_CHAIN_STATUS, (const uint8_t *)&status, sizeof(status)));
}

TEST_CASE("stan o blednej dlugosci jest naruszeniem protokolu", "[chain_net]") {
    prepare();

    chain_net_status_t status = make_status(1);
    TEST_ASSERT_FALSE(chain_net_handle_message(PEER_A, CMD_CHAIN_STATUS, (const uint8_t *)&status, sizeof(status) - 1));
}

TEST_CASE("synchronizacja startuje tylko przy wiekszej pracy drugiego wezla", "[chain_net]") {
    prepare();

    chain_tip_t tip;
    chain_get_tip(&tip);

    chain_net_status_t status = make_status(tip.cumulative_work);
    deliver(PEER_A, CMD_CHAIN_STATUS, &status, sizeof(status));
    TEST_ASSERT_EQUAL(0, s_frame_count);

    status = make_status(tip.cumulative_work + 1);
    deliver(PEER_A, CMD_CHAIN_STATUS, &status, sizeof(status));
    TEST_ASSERT_EQUAL(1, s_frame_count);
    TEST_ASSERT_EQUAL_UINT16(CMD_GET_BLOCKS, s_frames[0].cmd);
    TEST_ASSERT_EQUAL_INT8(PEER_A.slot, s_frames[0].peer.slot);
    TEST_ASSERT_EQUAL_UINT32(PEER_A.conn_id, s_frames[0].peer.conn_id);

    const chain_net_get_blocks_t *request = (const chain_net_get_blocks_t *)s_frames[0].data;
    uint8_t genesis_hash[KRST_HASH_SIZE];
    th_genesis_hash(genesis_hash);
    TEST_ASSERT_EQUAL_UINT16(1, request->count);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(genesis_hash, request->hashes[0], KRST_HASH_SIZE);

    deliver(PEER_B, CMD_CHAIN_STATUS, &status, sizeof(status));
    TEST_ASSERT_EQUAL(1, s_frame_count);
}

TEST_CASE("lokator krotkiego lancucha zawiera wszystkie bloki", "[chain_net]") {
    prepare();
    grow_chain(3);

    static uint8_t hashes[CHAIN_NET_MAX_LOCATOR][KRST_HASH_SIZE];
    chain_tip_t tip;
    uint8_t genesis_hash[KRST_HASH_SIZE];
    chain_get_tip(&tip);
    th_genesis_hash(genesis_hash);

    TEST_ASSERT_EQUAL_UINT16(4, chain_build_locator(hashes, CHAIN_NET_MAX_LOCATOR));
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tip.hash, hashes[0], KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(genesis_hash, hashes[3], KRST_HASH_SIZE);
}

TEST_CASE("lokator dlugiego lancucha miesci sie w limicie i konczy na genesis", "[chain_net]") {
    prepare();
    grow_chain(CHAIN_MAX_BLOCKS - 1);

    static uint8_t hashes[CHAIN_NET_MAX_LOCATOR][KRST_HASH_SIZE];
    chain_tip_t tip;
    uint8_t genesis_hash[KRST_HASH_SIZE];
    chain_get_tip(&tip);
    th_genesis_hash(genesis_hash);

    uint16_t count = chain_build_locator(hashes, CHAIN_NET_MAX_LOCATOR);
    TEST_ASSERT_LESS_OR_EQUAL_UINT16(CHAIN_NET_MAX_LOCATOR, count);
    TEST_ASSERT_GREATER_THAN_UINT16(8, count);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tip.hash, hashes[0], KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(genesis_hash, hashes[count - 1], KRST_HASH_SIZE);

    uint32_t previous = tip.height + 1;
    for (uint16_t i = 0; i < count; i++) {
        uint32_t height = 0;
        TEST_ASSERT_TRUE(chain_find_common_height((const uint8_t (*)[KRST_HASH_SIZE])hashes[i], 1, &height));
        TEST_ASSERT_LESS_THAN_UINT32(previous, height);
        previous = height;
    }
}

TEST_CASE("wspolny przodek pomija bloki spoza glownego lancucha", "[chain_net]") {
    prepare();

    uint8_t genesis_hash[KRST_HASH_SIZE];
    th_genesis_hash(genesis_hash);
    grow_chain(2);

    static block_t side;
    th_make_child(&side, genesis_hash, 0, CONSENSUS_GENESIS_TIMESTAMP, 1);
    TEST_ASSERT_EQUAL(CHAIN_SIDE_BRANCH, chain_accept_block(&side, NOW, false, NULL));

    static uint8_t hashes[2][KRST_HASH_SIZE];
    block_header_hash(&side.header, hashes[0]);
    memcpy(hashes[1], genesis_hash, KRST_HASH_SIZE);

    uint32_t height = 99;
    TEST_ASSERT_TRUE(chain_find_common_height(hashes, 2, &height));
    TEST_ASSERT_EQUAL_UINT32(0, height);

    memset(hashes[0], 0xEE, KRST_HASH_SIZE);
    TEST_ASSERT_FALSE(chain_find_common_height(hashes, 1, &height));
}

TEST_CASE("odpowiedz na prosbe o bloki idzie partiami", "[chain_net]") {
    prepare();
    grow_chain(CHAIN_NET_BATCH_SIZE + 3);

    static chain_net_get_blocks_t request;
    request.count = 1;
    th_genesis_hash(request.hashes[0]);
    deliver(PEER_A, CMD_GET_BLOCKS, &request, locator_length(1));

    TEST_ASSERT_EQUAL(CHAIN_NET_BATCH_SIZE + 1, s_frame_count);
    for (int i = 0; i < CHAIN_NET_BATCH_SIZE; i++) {
        TEST_ASSERT_EQUAL_UINT16(CMD_BLOCK, s_frames[i].cmd);
        TEST_ASSERT_EQUAL_UINT32(i + 1, frame_block_height(&s_frames[i]));
    }
    TEST_ASSERT_EQUAL_UINT16(CMD_BLOCKS_END, s_frames[CHAIN_NET_BATCH_SIZE].cmd);
    TEST_ASSERT_EQUAL_UINT8(1, s_frames[CHAIN_NET_BATCH_SIZE].data[0]);

    block_header_hash(&((const block_t *)s_frames[CHAIN_NET_BATCH_SIZE - 1].data)->header, request.hashes[0]);
    clear_frames();
    deliver(PEER_A, CMD_GET_BLOCKS, &request, locator_length(1));

    TEST_ASSERT_EQUAL(4, s_frame_count);
    TEST_ASSERT_EQUAL_UINT32(CHAIN_NET_BATCH_SIZE + 1, frame_block_height(&s_frames[0]));
    TEST_ASSERT_EQUAL_UINT32(CHAIN_NET_BATCH_SIZE + 3, frame_block_height(&s_frames[2]));
    TEST_ASSERT_EQUAL_UINT16(CMD_BLOCKS_END, s_frames[3].cmd);
    TEST_ASSERT_EQUAL_UINT8(0, s_frames[3].data[0]);
}

TEST_CASE("prosba od wezla na aktualnym tipie daje pusta odpowiedz", "[chain_net]") {
    prepare();
    grow_chain(2);

    chain_tip_t tip;
    chain_get_tip(&tip);

    static chain_net_get_blocks_t request;
    request.count = 1;
    memcpy(request.hashes[0], tip.hash, KRST_HASH_SIZE);
    deliver(PEER_A, CMD_GET_BLOCKS, &request, locator_length(1));

    TEST_ASSERT_EQUAL(1, s_frame_count);
    TEST_ASSERT_EQUAL_UINT16(CMD_BLOCKS_END, s_frames[0].cmd);
    TEST_ASSERT_EQUAL_UINT8(0, s_frames[0].data[0]);
}

TEST_CASE("niepoprawny lokator jest naruszeniem protokolu", "[chain_net]") {
    prepare();

    static chain_net_get_blocks_t request;
    const uint8_t *data = (const uint8_t *)&request;

    request.count = 0;
    TEST_ASSERT_FALSE(chain_net_handle_message(PEER_A, CMD_GET_BLOCKS, data, locator_length(0)));

    request.count = CHAIN_NET_MAX_LOCATOR + 1;
    TEST_ASSERT_FALSE(chain_net_handle_message(PEER_A, CMD_GET_BLOCKS, data, locator_length(CHAIN_NET_MAX_LOCATOR)));

    request.count = 2;
    TEST_ASSERT_FALSE(chain_net_handle_message(PEER_A, CMD_GET_BLOCKS, data, locator_length(1)));

    TEST_ASSERT_FALSE(chain_net_handle_message(PEER_A, CMD_GET_BLOCKS, data, 1));
}

TEST_CASE("nowy blok jest przyjmowany i rozsylany do wszystkich oprocz nadawcy", "[chain_net]") {
    prepare();
    make_tip_child(&s_block);
    deliver_block(PEER_A, CMD_NEW_BLOCK, &s_block);

    chain_tip_t tip;
    chain_get_tip(&tip);
    TEST_ASSERT_EQUAL_UINT32(1, tip.height);

    TEST_ASSERT_EQUAL(1, s_frame_count);
    TEST_ASSERT_EQUAL(FRAME_BROADCAST, s_frames[0].kind);
    TEST_ASSERT_EQUAL_UINT16(CMD_NEW_BLOCK, s_frames[0].cmd);
    TEST_ASSERT_TRUE(s_frames[0].has_exclude);
    TEST_ASSERT_EQUAL_INT8(PEER_A.slot, s_frames[0].peer.slot);
    TEST_ASSERT_EQUAL_UINT32(PEER_A.conn_id, s_frames[0].peer.conn_id);
    TEST_ASSERT_EQUAL_UINT32(block_serialized_size(&s_block), s_frames[0].length);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(&s_block, s_frames[0].data, s_frames[0].length);
}

TEST_CASE("blok wykopany lokalnie jest rozsylany do wszystkich", "[chain_net]") {
    prepare();

    block_t *block = malloc(sizeof(block_t));
    TEST_ASSERT_NOT_NULL(block);
    make_tip_child(block);
    TEST_ASSERT_TRUE(chain_task_submit_block(block, CHAIN_SOURCE_LOCAL, true, pdMS_TO_TICKS(1000)));
    th_wait_chain_idle();

    TEST_ASSERT_FALSE(s_record_failed);
    TEST_ASSERT_EQUAL(1, s_frame_count);
    TEST_ASSERT_EQUAL(FRAME_BROADCAST, s_frames[0].kind);
    TEST_ASSERT_EQUAL_INT8(-1, s_frames[0].peer.slot);
}

TEST_CASE("znany blok nie jest rozsylany ponownie", "[chain_net]") {
    prepare();
    make_tip_child(&s_block);
    deliver_block(PEER_A, CMD_NEW_BLOCK, &s_block);
    clear_frames();

    deliver_block(PEER_B, CMD_NEW_BLOCK, &s_block);
    TEST_ASSERT_EQUAL(0, s_frame_count);
    TEST_ASSERT_EQUAL(0, s_disconnect_count);
}

TEST_CASE("wezel wysylajacy niepoprawny blok jest rozlaczany", "[chain_net]") {
    prepare();
    make_tip_child(&s_block);
    s_block.txs[0].amount = CONSENSUS_BLOCK_REWARD + 1;
    th_finish(&s_block);
    deliver_block(PEER_B, CMD_NEW_BLOCK, &s_block);

    TEST_ASSERT_EQUAL(1, s_disconnect_count);
    TEST_ASSERT_EQUAL_INT8(PEER_B.slot, s_disconnected.slot);
    TEST_ASSERT_EQUAL_UINT32(PEER_B.conn_id, s_disconnected.conn_id);
    TEST_ASSERT_EQUAL(0, s_frame_count);

    chain_tip_t tip;
    chain_get_tip(&tip);
    TEST_ASSERT_EQUAL_UINT32(0, tip.height);
}

TEST_CASE("blok o zlym formacie jest naruszeniem protokolu", "[chain_net]") {
    prepare();
    make_tip_child(&s_block);
    uint32_t size = (uint32_t)block_serialized_size(&s_block);

    TEST_ASSERT_FALSE(chain_net_handle_message(PEER_A, CMD_NEW_BLOCK, (const uint8_t *)&s_block, size - 1));
    TEST_ASSERT_FALSE(chain_net_handle_message(PEER_A, CMD_BLOCK, (const uint8_t *)&s_block, 3));
}

TEST_CASE("blok z nieznanym rodzicem uruchamia synchronizacje z nadawca", "[chain_net]") {
    prepare();

    const uint8_t unknown_parent[KRST_HASH_SIZE] = { 0xDE, 0xAD };
    th_make_child(&s_block, unknown_parent, 5, CONSENSUS_GENESIS_TIMESTAMP, 0);
    deliver_block(PEER_B, CMD_NEW_BLOCK, &s_block);

    TEST_ASSERT_EQUAL(1, s_frame_count);
    TEST_ASSERT_EQUAL_UINT16(CMD_GET_BLOCKS, s_frames[0].cmd);
    TEST_ASSERT_EQUAL_INT8(PEER_B.slot, s_frames[0].peer.slot);
    TEST_ASSERT_EQUAL(0, s_disconnect_count);
}

TEST_CASE("blok z synchronizacji nie jest rozsylany", "[chain_net]") {
    prepare();
    make_tip_child(&s_block);
    deliver_block(PEER_A, CMD_BLOCK, &s_block);

    chain_tip_t tip;
    chain_get_tip(&tip);
    TEST_ASSERT_EQUAL_UINT32(1, tip.height);
    TEST_ASSERT_EQUAL(0, s_frame_count);
}

TEST_CASE("po calej synchronizacji sasiedzi dostaja nowy stan", "[chain_net]") {
    prepare();

    chain_tip_t tip;
    chain_get_tip(&tip);
    chain_net_status_t status = make_status(tip.cumulative_work + 1);
    deliver(PEER_A, CMD_CHAIN_STATUS, &status, sizeof(status));
    clear_frames();

    make_tip_child(&s_block);
    deliver_block(PEER_A, CMD_BLOCK, &s_block);

    const chain_net_blocks_end_t end = { .more = 0 };
    deliver(PEER_A, CMD_BLOCKS_END, &end, sizeof(end));

    TEST_ASSERT_EQUAL(1, s_frame_count);
    TEST_ASSERT_EQUAL(FRAME_BROADCAST, s_frames[0].kind);
    TEST_ASSERT_EQUAL_UINT16(CMD_CHAIN_STATUS, s_frames[0].cmd);
    TEST_ASSERT_EQUAL_UINT32(1, ((const chain_net_status_t *)s_frames[0].data)->height);
}

TEST_CASE("kolejna partia jest pobierana tylko przy postepie", "[chain_net]") {
    prepare();

    chain_tip_t tip;
    chain_get_tip(&tip);
    chain_net_status_t status = make_status(tip.cumulative_work + 1);
    deliver(PEER_A, CMD_CHAIN_STATUS, &status, sizeof(status));

    make_tip_child(&s_block);
    deliver_block(PEER_A, CMD_BLOCK, &s_block);
    clear_frames();

    const chain_net_blocks_end_t more = { .more = 1 };
    deliver(PEER_A, CMD_BLOCKS_END, &more, sizeof(more));
    TEST_ASSERT_EQUAL(1, s_frame_count);
    TEST_ASSERT_EQUAL_UINT16(CMD_GET_BLOCKS, s_frames[0].cmd);
    clear_frames();

    deliver(PEER_A, CMD_BLOCKS_END, &more, sizeof(more));
    for (int i = 0; i < s_frame_count; i++) {
        TEST_ASSERT_NOT_EQUAL(CMD_GET_BLOCKS, s_frames[i].cmd);
    }
}

TEST_CASE("koniec partii od innego wezla jest ignorowany", "[chain_net]") {
    prepare();

    chain_tip_t tip;
    chain_get_tip(&tip);
    chain_net_status_t status = make_status(tip.cumulative_work + 1);
    deliver(PEER_A, CMD_CHAIN_STATUS, &status, sizeof(status));
    clear_frames();

    const chain_net_blocks_end_t end = { .more = 1 };
    deliver(PEER_B, CMD_BLOCKS_END, &end, sizeof(end));
    TEST_ASSERT_EQUAL(0, s_frame_count);

    deliver(PEER_B, CMD_CHAIN_STATUS, &status, sizeof(status));
    TEST_ASSERT_EQUAL(0, s_frame_count);
}

// Rozpoczyna synchronizacje z wezlem A, ktory oglasza wieksza prace
static void begin_sync_with_peer_a(void) {
    chain_tip_t tip;
    chain_get_tip(&tip);
    chain_net_status_t status = make_status(tip.cumulative_work + 1);
    deliver(PEER_A, CMD_CHAIN_STATUS, &status, sizeof(status));
    clear_frames();
}

// Zglasza prace wieksza o podana wartosc od obecnego tipa
static void announce_extra_work(p2p_peer_ref_t peer, uint64_t extra) {
    chain_tip_t tip;
    chain_get_tip(&tip);
    chain_net_status_t status = make_status(tip.cumulative_work + extra);
    deliver(peer, CMD_CHAIN_STATUS, &status, sizeof(status));
}

// Konczy partie blokow od wezla A bez kolejnych
static void end_batch_from_peer_a(void) {
    const chain_net_blocks_end_t end = { .more = 0 };
    deliver(PEER_A, CMD_BLOCKS_END, &end, sizeof(end));
}

// Dostarcza od wezla A jedno dziecko aktualnego tipa
static void receive_one_block_from_peer_a(void) {
    make_tip_child(&s_block);
    deliver_block(PEER_A, CMD_BLOCK, &s_block);
}

// Sprawdza, ze ramka jest prosba o bloki do podanego wezla
static void assert_requests_blocks_from(const recorded_frame_t *frame, p2p_peer_ref_t peer) {
    TEST_ASSERT_EQUAL(FRAME_SEND, frame->kind);
    TEST_ASSERT_EQUAL_UINT16(CMD_GET_BLOCKS, frame->cmd);
    TEST_ASSERT_EQUAL_INT8(peer.slot, frame->peer.slot);
    TEST_ASSERT_EQUAL_UINT32(peer.conn_id, frame->peer.conn_id);
}

TEST_CASE("po synchronizacji wezel pobiera bloki od sasiada z wieksza praca", "[chain_net]") {
    prepare();
    begin_sync_with_peer_a();

    announce_extra_work(PEER_B, 1000);
    TEST_ASSERT_EQUAL(0, s_frame_count);

    receive_one_block_from_peer_a();
    end_batch_from_peer_a();

    TEST_ASSERT_EQUAL(2, s_frame_count);
    TEST_ASSERT_EQUAL_UINT16(CMD_CHAIN_STATUS, s_frames[0].cmd);
    assert_requests_blocks_from(&s_frames[1], PEER_B);

    chain_tip_t tip;
    chain_get_tip(&tip);
    const chain_net_get_blocks_t *request = (const chain_net_get_blocks_t *)s_frames[1].data;
    TEST_ASSERT_EQUAL_HEX8_ARRAY(tip.hash, request->hashes[0], KRST_HASH_SIZE);
}

TEST_CASE("sasiad bez przewagi po synchronizacji nie jest odpytywany", "[chain_net]") {
    prepare();
    begin_sync_with_peer_a();

    announce_extra_work(PEER_B, 1);
    receive_one_block_from_peer_a();
    end_batch_from_peer_a();

    TEST_ASSERT_EQUAL(1, s_frame_count);
    TEST_ASSERT_EQUAL_UINT16(CMD_CHAIN_STATUS, s_frames[0].cmd);
}

TEST_CASE("wezel klamiacy o pracy nie blokuje pobrania blokow od uczciwego sasiada", "[chain_net]") {
    prepare();
    begin_sync_with_peer_a();

    announce_extra_work(PEER_B, 1000);

    end_batch_from_peer_a();

    TEST_ASSERT_EQUAL(1, s_frame_count);
    assert_requests_blocks_from(&s_frames[0], PEER_B);
}

TEST_CASE("z kilku sasiadow wybierany jest ten z najwieksza praca", "[chain_net]") {
    prepare();
    begin_sync_with_peer_a();

    const p2p_peer_ref_t peer_c = { .slot = 2, .conn_id = 303 };
    announce_extra_work(PEER_B, 500);
    announce_extra_work(peer_c, 1000);
    announce_extra_work(PEER_B, 700);

    end_batch_from_peer_a();

    TEST_ASSERT_EQUAL(1, s_frame_count);
    assert_requests_blocks_from(&s_frames[0], peer_c);
}

TEST_CASE("nadawca orphana w trakcie synchronizacji jest odpytywany po jej koncu", "[chain_net]") {
    prepare();
    begin_sync_with_peer_a();

    const uint8_t unknown_parent[KRST_HASH_SIZE] = { 0xDE, 0xAD };
    th_make_child(&s_block, unknown_parent, 5, CONSENSUS_GENESIS_TIMESTAMP, 0);
    deliver_block(PEER_B, CMD_NEW_BLOCK, &s_block);
    TEST_ASSERT_EQUAL(0, s_frame_count);
    TEST_ASSERT_EQUAL(0, s_disconnect_count);

    receive_one_block_from_peer_a();
    end_batch_from_peer_a();

    TEST_ASSERT_EQUAL(2, s_frame_count);
    assert_requests_blocks_from(&s_frames[1], PEER_B);
}

TEST_CASE("sasiad odpytany po synchronizacji nie powoduje zapetlenia", "[chain_net]") {
    prepare();
    begin_sync_with_peer_a();

    announce_extra_work(PEER_B, 1000);
    end_batch_from_peer_a();
    clear_frames();

    const chain_net_blocks_end_t end = { .more = 0 };
    deliver(PEER_B, CMD_BLOCKS_END, &end, sizeof(end));
    TEST_ASSERT_EQUAL(0, s_frame_count);

    announce_extra_work(PEER_A, 1);
    TEST_ASSERT_EQUAL(1, s_frame_count);
    assert_requests_blocks_from(&s_frames[0], PEER_A);
}

static SemaphoreHandle_t s_jam_started = NULL;
static SemaphoreHandle_t s_jam_release = NULL;

// Praca blokujaca zadanie lancucha do czasu zwolnienia
static void jam_work(void *arg, p2p_peer_ref_t source) {
    (void)arg;
    (void)source;
    xSemaphoreGive(s_jam_started);
    xSemaphoreTake(s_jam_release, portMAX_DELAY);
}

// Pusta praca do zapelnienia kolejki
static void noop_work(void *arg, p2p_peer_ref_t source) {
    (void)arg;
    (void)source;
}

// Blokuje zadanie lancucha i zapelnia jego kolejke
static void jam_chain_queue(void) {
    if (s_jam_started == NULL) {
        s_jam_started = xSemaphoreCreateBinary();
        s_jam_release = xSemaphoreCreateBinary();
        TEST_ASSERT_NOT_NULL(s_jam_started);
        TEST_ASSERT_NOT_NULL(s_jam_release);
    }

    TEST_ASSERT_TRUE(chain_task_post_work(jam_work, NULL, CHAIN_SOURCE_LOCAL, pdMS_TO_TICKS(1000)));
    TEST_ASSERT_EQUAL(pdTRUE, xSemaphoreTake(s_jam_started, pdMS_TO_TICKS(5000)));
    while (chain_task_post_work(noop_work, NULL, CHAIN_SOURCE_LOCAL, 0)) {
    }
}

// Odblokowuje zadanie lancucha i czeka na oproznienie kolejki
static void release_chain_queue(void) {
    xSemaphoreGive(s_jam_release);
    th_wait_chain_idle();
}

static block_t s_batch[3];

// Buduje kolejne bloki od obecnego tipa, kazdy jest dzieckiem poprzedniego
static void build_batch(int count) {
    chain_tip_t tip;
    chain_get_tip(&tip);

    uint8_t parent_hash[KRST_HASH_SIZE];
    memcpy(parent_hash, tip.hash, KRST_HASH_SIZE);
    uint32_t parent_height = tip.height;
    uint32_t parent_timestamp = tip.timestamp;

    for (int i = 0; i < count; i++) {
        th_make_child(&s_batch[i], parent_hash, parent_height, parent_timestamp, 0);
        block_header_hash(&s_batch[i].header, parent_hash);
        parent_height = s_batch[i].header.height;
        parent_timestamp = s_batch[i].header.timestamp;
    }
}

// Przekazanie bloku bez czekania na zadanie lancucha. Zwraca czas trwania w tickach.
static TickType_t hand_over_block(p2p_peer_ref_t peer, const block_t *block) {
    TickType_t start = xTaskGetTickCount();
    TEST_ASSERT_TRUE(chain_net_handle_message(peer, CMD_BLOCK, (const uint8_t *)block,
                                              (uint32_t)block_serialized_size(block)));
    return xTaskGetTickCount() - start;
}

// Wysokosc aktualnego tipa
static uint32_t tip_height(void) {
    chain_tip_t tip;
    chain_get_tip(&tip);
    return tip.height;
}

TEST_CASE("po porzuconym bloku reszta partii jest pomijana bez czekania na kolejke", "[chain_net]") {
    prepare();
    begin_sync_with_peer_a();
    build_batch(2);

    jam_chain_queue();
    TEST_ASSERT_GREATER_OR_EQUAL_UINT32(pdMS_TO_TICKS(900), hand_over_block(PEER_A, &s_batch[0]));
    TEST_ASSERT_LESS_THAN_UINT32(pdMS_TO_TICKS(200), hand_over_block(PEER_A, &s_batch[1]));
    release_chain_queue();

    TEST_ASSERT_EQUAL_UINT32(0, tip_height());
}

TEST_CASE("koniec partii konczy pomijanie i wznawia pobieranie od luki", "[chain_net]") {
    prepare();
    begin_sync_with_peer_a();
    build_batch(3);

    deliver_block(PEER_A, CMD_BLOCK, &s_batch[0]);
    TEST_ASSERT_EQUAL_UINT32(1, tip_height());

    jam_chain_queue();
    hand_over_block(PEER_A, &s_batch[1]);
    hand_over_block(PEER_A, &s_batch[2]);
    release_chain_queue();
    TEST_ASSERT_EQUAL_UINT32(1, tip_height());

    clear_frames();
    const chain_net_blocks_end_t more = { .more = 1 };
    deliver(PEER_A, CMD_BLOCKS_END, &more, sizeof(more));

    TEST_ASSERT_EQUAL(1, s_frame_count);
    assert_requests_blocks_from(&s_frames[0], PEER_A);
    uint8_t first_hash[KRST_HASH_SIZE];
    block_header_hash(&s_batch[0].header, first_hash);
    const chain_net_get_blocks_t *request = (const chain_net_get_blocks_t *)s_frames[0].data;
    TEST_ASSERT_EQUAL_HEX8_ARRAY(first_hash, request->hashes[0], KRST_HASH_SIZE);

    deliver_block(PEER_A, CMD_BLOCK, &s_batch[1]);
    TEST_ASSERT_EQUAL_UINT32(2, tip_height());
}

TEST_CASE("pomijanie dotyczy tylko polaczenia, ktore stracilo blok, i tylko CMD_BLOCK", "[chain_net]") {
    prepare();
    begin_sync_with_peer_a();
    build_batch(3);

    jam_chain_queue();
    hand_over_block(PEER_A, &s_batch[0]);
    release_chain_queue();

    deliver_block(PEER_B, CMD_BLOCK, &s_batch[0]);
    TEST_ASSERT_EQUAL_UINT32(1, tip_height());

    deliver_block(PEER_A, CMD_BLOCK, &s_batch[1]);
    TEST_ASSERT_EQUAL_UINT32(1, tip_height());

    const p2p_peer_ref_t peer_a_reconnected = { .slot = PEER_A.slot, .conn_id = PEER_A.conn_id + 1 };
    deliver_block(peer_a_reconnected, CMD_BLOCK, &s_batch[1]);
    TEST_ASSERT_EQUAL_UINT32(2, tip_height());

    deliver_block(PEER_A, CMD_NEW_BLOCK, &s_batch[2]);
    TEST_ASSERT_EQUAL_UINT32(3, tip_height());
}

// Okresowe sprawdzenie z przesunietym czasem, wykonywane w zadaniu lancucha
static void tick_work(void *arg, p2p_peer_ref_t source) {
    (void)source;
    chain_net_tick(*(const TickType_t *)arg);
}

// Uruchamia okresowe sprawdzenie tak, jakby minelo podane ms
static void run_tick_after(uint32_t ms) {
    static TickType_t now;
    now = xTaskGetTickCount() + pdMS_TO_TICKS(ms);
    TEST_ASSERT_TRUE(chain_task_post_work(tick_work, &now, CHAIN_SOURCE_LOCAL, pdMS_TO_TICKS(1000)));
    th_wait_chain_idle();
    TEST_ASSERT_FALSE(s_record_failed);
}

TEST_CASE("prosba o stan dostaje w odpowiedzi stan lancucha", "[chain_net]") {
    prepare();
    grow_chain(1);

    TEST_ASSERT_TRUE(chain_net_handle_message(PEER_B, CMD_GET_STATUS, NULL, 0));
    TEST_ASSERT_EQUAL(1, s_frame_count);
    TEST_ASSERT_EQUAL(FRAME_SEND, s_frames[0].kind);
    TEST_ASSERT_EQUAL_UINT16(CMD_CHAIN_STATUS, s_frames[0].cmd);
    TEST_ASSERT_EQUAL_INT8(PEER_B.slot, s_frames[0].peer.slot);
    TEST_ASSERT_EQUAL_UINT32(1, ((const chain_net_status_t *)s_frames[0].data)->height);

    const uint8_t data[1] = { 0 };
    TEST_ASSERT_FALSE(chain_net_handle_message(PEER_B, CMD_GET_STATUS, data, sizeof(data)));
}

TEST_CASE("synchronizacja bez odpowiedzi przez 15 s jest przerywana i wezel pyta wszystkich o stan", "[chain_net]") {
    prepare();
    begin_sync_with_peer_a();

    run_tick_after(14000);
    TEST_ASSERT_EQUAL(0, s_frame_count);

    run_tick_after(16000);
    TEST_ASSERT_EQUAL(1, s_frame_count);
    TEST_ASSERT_EQUAL(FRAME_BROADCAST, s_frames[0].kind);
    TEST_ASSERT_FALSE(s_frames[0].has_exclude);
    TEST_ASSERT_EQUAL_UINT16(CMD_GET_STATUS, s_frames[0].cmd);
    TEST_ASSERT_EQUAL_UINT32(0, s_frames[0].length);
    clear_frames();

    const chain_net_blocks_end_t more = { .more = 1 };
    deliver(PEER_A, CMD_BLOCKS_END, &more, sizeof(more));
    TEST_ASSERT_EQUAL(0, s_frame_count);

    announce_extra_work(PEER_B, 10);
    TEST_ASSERT_EQUAL(1, s_frame_count);
    assert_requests_blocks_from(&s_frames[0], PEER_B);
}

TEST_CASE("okresowe sprawdzenie bez synchronizacji niczego nie wysyla", "[chain_net]") {
    prepare();
    run_tick_after(60000);
    TEST_ASSERT_EQUAL(0, s_frame_count);
}

TEST_CASE("koniec partii o zlej dlugosci jest naruszeniem protokolu", "[chain_net]") {
    prepare();
    const uint8_t data[2] = { 0, 0 };
    TEST_ASSERT_FALSE(chain_net_handle_message(PEER_A, CMD_BLOCKS_END, data, sizeof(data)));
}

TEST_CASE("nieznana komenda nie zrywa polaczenia", "[chain_net]") {
    prepare();
    TEST_ASSERT_TRUE(chain_net_handle_message(PEER_A, 999, NULL, 0));
}

TEST_CASE("bloki wyslane przez wezel odtwarzaja ten sam lancuch i salda po synchronizacji", "[chain_net]") {
    prepare();

    static const int total = CHAIN_NET_BATCH_SIZE + 2;
    grow_chain(total);

    chain_tip_t source_tip;
    chain_get_tip(&source_tip);

    block_t *blocks = malloc(total * sizeof(block_t));
    TEST_ASSERT_NOT_NULL(blocks);
    uint32_t sizes[CHAIN_NET_BATCH_SIZE + 2];

    static chain_net_get_blocks_t request;
    request.count = 1;
    th_genesis_hash(request.hashes[0]);
    deliver(PEER_A, CMD_GET_BLOCKS, &request, locator_length(1));
    TEST_ASSERT_EQUAL(CHAIN_NET_BATCH_SIZE + 1, s_frame_count);
    for (int i = 0; i < CHAIN_NET_BATCH_SIZE; i++) {
        memcpy(&blocks[i], s_frames[i].data, s_frames[i].length);
        sizes[i] = s_frames[i].length;
    }

    block_header_hash(&blocks[CHAIN_NET_BATCH_SIZE - 1].header, request.hashes[0]);
    clear_frames();
    deliver(PEER_A, CMD_GET_BLOCKS, &request, locator_length(1));
    TEST_ASSERT_EQUAL(3, s_frame_count);
    for (int i = 0; i < 2; i++) {
        memcpy(&blocks[CHAIN_NET_BATCH_SIZE + i], s_frames[i].data, s_frames[i].length);
        sizes[CHAIN_NET_BATCH_SIZE + i] = s_frames[i].length;
    }

    TEST_ASSERT_EQUAL(ESP_OK, chain_reset());
    clear_frames();
    for (int i = 0; i < total; i++) {
        deliver(PEER_B, CMD_BLOCK, &blocks[i], sizes[i]);
    }
    TEST_ASSERT_EQUAL(0, s_disconnect_count);

    chain_tip_t synced_tip;
    chain_get_tip(&synced_tip);
    TEST_ASSERT_EQUAL_HEX8_ARRAY(source_tip.hash, synced_tip.hash, KRST_HASH_SIZE);
    TEST_ASSERT_EQUAL_UINT32(source_tip.height, synced_tip.height);
    TEST_ASSERT_EQUAL_UINT64(source_tip.cumulative_work, synced_tip.cumulative_work);
    TEST_ASSERT_EQUAL_UINT64(total * CONSENSUS_BLOCK_REWARD, ledger_get_balance(blocks[0].txs[0].recipient));

    free(blocks);
}
