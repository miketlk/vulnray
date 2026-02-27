#include <stdint.h>
#include <string.h>

// Typical firmware parser issue: attacker-controlled length copied into fixed buffer.
int unsafe_packet_copy(const uint8_t *packet, uint16_t packet_len) {
    uint8_t local[64];
    uint16_t copy_len = (packet[0] << 8) | packet[1];
    if (packet_len < 2) {
        return -1;
    }
    memcpy(local, packet + 2, copy_len);
    return local[0];
}

// Off-by-one in framing code.
void append_crc_byte(uint8_t *frame, uint16_t len, uint8_t crc) {
    if (len <= 256) {
        frame[len] = crc;
    }
}
