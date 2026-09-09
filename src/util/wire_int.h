#ifndef MLDSA_AUTH_UTIL_WIRE_INT_H
#define MLDSA_AUTH_UTIL_WIRE_INT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Fixed-width big-endian integer read/write helpers used by the wire
 * format (Section 6.4's convention; Security Requirement 4.6: strict
 * length validation before parsing).
 *
 * Named `wire_int`, not `varint`: every length-prefix field in this
 * protocol's wire format has a small, bounded size (client_id <= 64,
 * signatures <= MLDSA_SIGNATURE_MAX_BYTES), so a general LEB128-style
 * variable-length integer encoding would add complexity -- and a second,
 * competing integer convention alongside the fixed big-endian one already
 * established -- for no benefit. These are plain u8/u16 read/write
 * helpers, nothing more.
 */

/* Writes a single byte to *out. Always succeeds (no bounds check --
 * callers are expected to have already validated output capacity, per
 * the encoder validation contract in protocol/transcript.h). */
void wire_int_write_u8(uint8_t *out, uint8_t value);

/* Writes a 2-byte big-endian value to out[0..1]. */
void wire_int_write_u16(uint8_t *out, uint16_t value);

/* Reads a single byte from buf[0], if `len` >= 1. Returns 0 on success,
 * nonzero if `len` < 1 (nothing read, *out left unmodified). */
int wire_int_read_u8(const uint8_t *buf, size_t len, uint8_t *out);

/* Reads a 2-byte big-endian value from buf[0..1], if `len` >= 2. Returns
 * 0 on success, nonzero if `len` < 2 (nothing read, *out left
 * unmodified). */
int wire_int_read_u16(const uint8_t *buf, size_t len, uint16_t *out);

#endif /* MLDSA_AUTH_UTIL_WIRE_INT_H */
