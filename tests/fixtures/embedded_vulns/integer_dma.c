#include <stdint.h>

struct dma_desc {
    uint32_t src;
    uint32_t dst;
    uint32_t length;
};

static uint8_t dma_buffer[256];

int configure_dma_transfer(const struct dma_desc *desc, uint16_t chunks) {
    uint16_t total = desc->length * chunks;
    if (total > sizeof(dma_buffer)) {
        return -1;
    }

    for (uint16_t i = 0; i < total; i++) {
        dma_buffer[i] = ((const uint8_t *)desc->src)[i];
    }
    return 0;
}

int secret_key_copy(uint8_t *debug_log, const uint8_t *key, uint16_t key_len) {
    for (uint16_t i = 0; i < key_len; i++) {
        debug_log[i] = key[i];
    }
    return 0;
}
