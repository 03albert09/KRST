#include "block_store.h"
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"
#include "esp_partition.h"
#include "esp_random.h"
#include "esp_rom_crc.h"

static const char *TAG = "BLOCK_STORE";

#define STORE_PARTITION_SUBTYPE 0x40
#define STORE_PARTITION_LABEL   "chain"
#define SUPERBLOCK_MAGIC        0x5453524Bu
#define RECORD_MAGIC            0x314B4C42u

typedef struct __attribute__((packed)) {
    uint32_t magic;                      // czy to nasz dziennik
    uint32_t log_id;                     // losowy przy formacie, unieważnia stare rekordy
    uint8_t  network_id[KRST_HASH_SIZE]; // z jakiej sieci bloki
    uint32_t crc;                        // CRC superbloku
} superblock_t;

typedef struct __attribute__((packed)) {
    uint32_t magic;  // początek rekordu
    uint32_t log_id; // musi = superblok
    uint32_t length; // rozmiar bloku
    uint32_t crc;    // CRC bloku (urwany zapis)
} record_header_t;

_Static_assert(sizeof(record_header_t) == BLOCK_STORE_RECORD_HEADER_SIZE, "Rozmiar naglowka rekordu");

static const esp_partition_t *s_partition = NULL;
static uint8_t s_network_id[KRST_HASH_SIZE];
static uint32_t s_log_id = 0;
static uint32_t s_write_pos = 0;

// Początek następnego sektora
static uint32_t next_sector(uint32_t pos) {
    return (pos / BLOCK_STORE_SECTOR_SIZE + 1) * BLOCK_STORE_SECTOR_SIZE;
}

// Odczyt i pełna kontrola rekordu. Rekord nie może przekraczać granicy sektora.
static bool read_record(uint32_t pos, block_t *out_block, uint32_t *out_record_size) {
    uint32_t sector_end = next_sector(pos);
    if (pos + sizeof(record_header_t) > sector_end || sector_end > s_partition->size) {
        return false;
    }

    record_header_t header;
    if (esp_partition_read(s_partition, pos, &header, sizeof(header)) != ESP_OK) {
        return false;
    }
    if (header.magic != RECORD_MAGIC || header.log_id != s_log_id || header.length > sizeof(block_t) ||
        pos + sizeof(header) + header.length > sector_end) {
        return false;
    }

    if (esp_partition_read(s_partition, pos + sizeof(header), out_block, header.length) != ESP_OK) {
        return false;
    }
    if (esp_rom_crc32_le(0, (const uint8_t *)out_block, header.length) != header.crc) {
        return false;
    }

    size_t base_size = offsetof(block_t, txs);
    if (header.length < base_size || out_block->tx_count > BLOCK_MAX_TX ||
        block_serialized_size(out_block) != header.length) {
        return false;
    }

    if (out_record_size) {
        *out_record_size = sizeof(header) + header.length;
    }
    return true;
}

// Sprawdzenie, czy reszta sektora jest skasowana
static bool sector_rest_is_blank(uint32_t pos) {
    uint8_t chunk[64];
    uint32_t sector_end = next_sector(pos);

    while (pos < sector_end) {
        uint32_t len = sector_end - pos;
        if (len > sizeof(chunk)) len = sizeof(chunk);
        if (esp_partition_read(s_partition, pos, chunk, len) != ESP_OK) {
            return false;
        }
        for (uint32_t i = 0; i < len; i++) {
            if (chunk[i] != 0xFF) return false;
        }
        pos += len;
    }
    return true;
}

// Przejście przez dziennik i ustalenie miejsca kolejnego zapisu
static esp_err_t scan_log(block_store_visit_fn visit, void *ctx) {
    block_t *block = malloc(sizeof(block_t));
    if (block == NULL) {
        return ESP_ERR_NO_MEM;
    }

    uint32_t pos = BLOCK_STORE_FIRST_RECORD;
    while (pos < s_partition->size) {
        uint32_t record_size = 0;
        if (read_record(pos, block, &record_size)) {
            if (visit) visit(block, pos, ctx);
            pos += record_size;
            continue;
        }

        uint32_t next = next_sector(pos);
        if (next < s_partition->size && read_record(next, block, NULL)) {
            pos = next;
            continue;
        }
        break;
    }

    if (pos < s_partition->size && pos % BLOCK_STORE_SECTOR_SIZE != 0 && !sector_rest_is_blank(pos)) {
        ESP_LOGW(TAG, "Uszkodzony rekord pod 0x%lx. Zapis przechodzi do nastepnego sektora.", (unsigned long)pos);
        pos = next_sector(pos);
    }
    s_write_pos = pos;

    free(block);
    return ESP_OK;
}

// Rozpoczęcie nowego dziennika
esp_err_t block_store_format(void) {
    if (s_partition == NULL) {
        return ESP_ERR_INVALID_STATE;
    }

    esp_err_t err = esp_partition_erase_range(s_partition, 0, BLOCK_STORE_SECTOR_SIZE);
    if (err != ESP_OK) {
        return err;
    }

    superblock_t superblock = {
        .magic = SUPERBLOCK_MAGIC,
        .log_id = esp_random() | 1u,
    };
    memcpy(superblock.network_id, s_network_id, sizeof(superblock.network_id));
    superblock.crc = esp_rom_crc32_le(0, (const uint8_t *)&superblock, offsetof(superblock_t, crc));

    err = esp_partition_write(s_partition, 0, &superblock, sizeof(superblock));
    if (err != ESP_OK) {
        return err;
    }

    s_log_id = superblock.log_id;
    s_write_pos = BLOCK_STORE_FIRST_RECORD;
    return ESP_OK;
}

// Otwarcie dziennika i odtworzenie zapisanych bloków
esp_err_t block_store_open(const uint8_t network_id[KRST_HASH_SIZE], block_store_visit_fn visit, void *ctx) {
    if (s_partition == NULL) {
        s_partition = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, STORE_PARTITION_SUBTYPE, STORE_PARTITION_LABEL);
        if (s_partition == NULL) {
            ESP_LOGE(TAG, "Brak partycji '%s'. Czy wgrano nowa tabele partycji?", STORE_PARTITION_LABEL);
            return ESP_ERR_NOT_FOUND;
        }
    }
    memcpy(s_network_id, network_id, sizeof(s_network_id));

    superblock_t superblock;
    esp_err_t err = esp_partition_read(s_partition, 0, &superblock, sizeof(superblock));
    if (err != ESP_OK) {
        return err;
    }

    bool valid = superblock.magic == SUPERBLOCK_MAGIC &&
                 superblock.crc == esp_rom_crc32_le(0, (const uint8_t *)&superblock, offsetof(superblock_t, crc)) &&
                 memcmp(superblock.network_id, network_id, KRST_HASH_SIZE) == 0;
    if (!valid) {
        ESP_LOGW(TAG, "Dziennik pusty albo z innej sieci. Formatowanie.");
        return block_store_format();
    }

    s_log_id = superblock.log_id;
    return scan_log(visit, ctx);
}

// Dopisanie bloku do dziennika
esp_err_t block_store_append(const block_t *block, uint32_t *out_offset) {
    if (s_partition == NULL || s_log_id == 0) {
        return ESP_ERR_INVALID_STATE;
    }
    if (block->tx_count > BLOCK_MAX_TX) {
        return ESP_ERR_INVALID_ARG;
    }

    uint32_t length = (uint32_t)block_serialized_size(block);
    uint32_t record_size = sizeof(record_header_t) + length;
    uint32_t pos = s_write_pos;

    if (pos + record_size > next_sector(pos)) {
        pos = next_sector(pos);
    }
    if (pos + record_size > s_partition->size) {
        return ESP_ERR_NO_MEM;
    }

    if (pos % BLOCK_STORE_SECTOR_SIZE == 0) {
        esp_err_t err = esp_partition_erase_range(s_partition, pos, BLOCK_STORE_SECTOR_SIZE);
        if (err != ESP_OK) {
            return err;
        }
    }

    record_header_t header = {
        .magic = RECORD_MAGIC,
        .log_id = s_log_id,
        .length = length,
        .crc = esp_rom_crc32_le(0, (const uint8_t *)block, length),
    };

    esp_err_t err = esp_partition_write(s_partition, pos + sizeof(header), block, length);
    if (err == ESP_OK) {
        err = esp_partition_write(s_partition, pos, &header, sizeof(header));
    }
    if (err != ESP_OK) {
        s_write_pos = next_sector(pos);
        return err;
    }

    s_write_pos = pos + record_size;
    if (out_offset) {
        *out_offset = pos;
    }
    return ESP_OK;
}

// Odczyt bloku z dziennika
esp_err_t block_store_read(uint32_t offset, block_t *out_block) {
    if (s_partition == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    return read_record(offset, out_block, NULL) ? ESP_OK : ESP_ERR_NOT_FOUND;
}
