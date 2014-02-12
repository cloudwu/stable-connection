#ifndef encrypt_h
#define encrypt_h

#include <stdint.h>
#include <stddef.h>

uint64_t powmodp(uint64_t a, uint64_t b);
uint64_t randomint64();
uint64_t hmac(uint64_t x, uint64_t y);

struct rc4_sbox {
	int i;
	int j;
	uint32_t fingerprint;
	uint8_t sbox[256];
};

uint32_t rc4_init(struct rc4_sbox *rs, uint64_t seed);
uint32_t rc4_encode(struct rc4_sbox *rs, const uint8_t *src, uint8_t *des, size_t sz);

#endif

