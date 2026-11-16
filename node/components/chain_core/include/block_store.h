#ifndef BLOCK_STORE_H
#define BLOCK_STORE_H

#include <stdint.h>
#include "esp_err.h"
#include "block.h"

#define BLOCK_STORE_SECTOR_SIZE         4096
#define BLOCK_STORE_FIRST_RECORD        BLOCK_STORE_SECTOR_SIZE
#define BLOCK_STORE_RECORD_HEADER_SIZE  16

// callback na każdy blok przy skanie dziennika
typedef void (*block_store_visit_fn)(const block_t *block, uint32_t offset, void *ctx);

// otwórz dziennik, inna sieć = format, visit na każdy blok
esp_err_t block_store_open(const uint8_t network_id[KRST_HASH_SIZE], block_store_visit_fn visit, void *ctx);

// nowy log_id, kasuje tylko superblok
esp_err_t block_store_format(void);

// dopisz blok, zwraca offset, ESP_ERR_NO_MEM = pełny
esp_err_t block_store_append(const block_t *block, uint32_t *out_offset);

// odczyt bloku spod offsetu
esp_err_t block_store_read(uint32_t offset, block_t *out_block);

#endif
