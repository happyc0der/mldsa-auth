#include "wire_int.h"

void wire_int_write_u8(uint8_t *out, uint8_t value) {
    out[0] = value;
}

void wire_int_write_u16(uint8_t *out, uint16_t value) {
    out[0] = (uint8_t)((value >> 8) & 0xFF);
    out[1] = (uint8_t)(value & 0xFF);
}

int wire_int_read_u8(const uint8_t *buf, size_t len, uint8_t *out) {
    if (len < 1) {
        return -1;
    }
    *out = buf[0];
    return 0;
}

int wire_int_read_u16(const uint8_t *buf, size_t len, uint16_t *out) {
    if (len < 2) {
        return -1;
    }
    *out = (uint16_t)(((uint16_t)buf[0] << 8) | (uint16_t)buf[1]);
    return 0;
}
