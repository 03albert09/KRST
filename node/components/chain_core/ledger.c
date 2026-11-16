#include "ledger.h"
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

typedef struct {
    uint8_t  address[KRST_PUBKEY_SIZE]; // klucz publiczny
    uint64_t balance;                   // saldo
} ledger_account_t;

static ledger_account_t s_accounts[LEDGER_MAX_ACCOUNTS];
static int s_account_count = 0;
static SemaphoreHandle_t s_lock = NULL;

// Wyszukanie konta po adresie
static int find_account(const uint8_t address[KRST_PUBKEY_SIZE]) {
    for (int i = 0; i < s_account_count; i++) {
        if (memcmp(s_accounts[i].address, address, KRST_PUBKEY_SIZE) == 0) {
            return i;
        }
    }
    return -1;
}

// Wyzerowanie wszystkich kont
void ledger_reset(void) {
    if (s_lock == NULL) {
        s_lock = xSemaphoreCreateMutex();
        configASSERT(s_lock != NULL);
    }

    xSemaphoreTake(s_lock, portMAX_DELAY);
    s_account_count = 0;
    memset(s_accounts, 0, sizeof(s_accounts));
    xSemaphoreGive(s_lock);
}

// Sprawdzenie, czy odbiorca coinbase zmieści się w tabeli
bool ledger_can_apply_block(const block_t *block) {
    return find_account(block->txs[0].recipient) >= 0 || s_account_count < LEDGER_MAX_ACCOUNTS;
}

// Dopisanie nagrody z coinbase do salda górnika
void ledger_apply_block(const block_t *block) {
    const krst_tx_t *coinbase = &block->txs[0];

    xSemaphoreTake(s_lock, portMAX_DELAY);
    int index = find_account(coinbase->recipient);
    if (index < 0) {
        index = s_account_count++;
        memcpy(s_accounts[index].address, coinbase->recipient, KRST_PUBKEY_SIZE);
    }
    s_accounts[index].balance += coinbase->amount;
    xSemaphoreGive(s_lock);
}

// Odczyt salda konta
uint64_t ledger_get_balance(const uint8_t address[KRST_PUBKEY_SIZE]) {
    xSemaphoreTake(s_lock, portMAX_DELAY);
    int index = find_account(address);
    uint64_t balance = index >= 0 ? s_accounts[index].balance : 0;
    xSemaphoreGive(s_lock);
    return balance;
}
