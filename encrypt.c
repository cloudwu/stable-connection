#include "encrypt.h"

// The biggest 64bit prime
#define P 0xffffffffffffffc5ull

#include <stdio.h>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>

static inline uint64_t
mul_mod_p(uint64_t a, uint64_t b) {
	uint64_t m = 0;
	while(b) {
		if(b&1) {
			uint64_t t = P-a;
			if ( m >= t) {
				m -= t;
			} else {
				m += a;
			}
		}
		if (a >= P - a) {
			a = a * 2 - P;
		} else {
			a = a * 2;
		}
		b>>=1;
	}
	return m;
}

static inline uint64_t
pow_mod_p(uint64_t a, uint64_t b) {
	if (b==1) {
		return a;
	}
	uint64_t t = pow_mod_p(a, b>>1);
	t = mul_mod_p(t,t);
	if (b % 2) {
		t = mul_mod_p(t, a);
	}
	return t;
}

// calc a^b % p
uint64_t
powmodp(uint64_t a, uint64_t b) {
	if (a > P)
		a%=P;
	return pow_mod_p(a,b);
}

uint64_t
randomint64() {
	uint64_t a = rand();
	uint64_t b = rand() & 0xffff;
	uint64_t c = rand() & 0xffff;
	uint64_t d = (rand() & 0xffff) + 1;	// avoid result 0
	return a << 48 | b << 32 | c << 16 | d;
}

// Constants are the integer part of the sines of integers (in radians) * 2^32.
const uint32_t k[64] = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee ,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501 ,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be ,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821 ,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa ,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8 ,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed ,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a ,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c ,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70 ,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05 ,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665 ,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039 ,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1 ,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1 ,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
 
// r specifies the per-round shift amounts
const uint32_t r[] = {7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
					  5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
					  4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
					  6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21};
 
// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
 
uint64_t
hmac(uint64_t x, uint64_t y) {
	uint32_t w[16];
	uint32_t a, b, c, d, f, g, temp;
	int i;
 
	a = 0x67452301u;
	b = 0xefcdab89u;
	c = 0x98badcfeu;
	d = 0x10325476u;

	for (i=0;i<16;i+=4) {
		w[i] = (uint32_t)(x >> 32);
		w[i+1] = (uint32_t)x;
		w[i+2] = (uint32_t)(y >> 32);
		w[i+3] = (uint32_t)y;
	}

	for(i = 0; i<64; i++) {
		if (i < 16) {
			f = (b & c) | ((~b) & d);
			g = i;
		} else if (i < 32) {
			f = (d & b) | ((~d) & c);
			g = (5*i + 1) % 16;
		} else if (i < 48) {
			f = b ^ c ^ d;
			g = (3*i + 5) % 16; 
		} else {
			f = c ^ (b | (~d));
			g = (7*i) % 16;
		}

		temp = d;
		d = c;
		c = b;
		b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
		a = temp;

	}

	return (uint64_t)(a^b) << 32 | (c^d);
}

uint32_t 
rc4_init(struct rc4_sbox *rs, uint64_t seed) {
	seed = hmac(seed,0);
	rs->i=0;
	rs->j=0;
	rs->fingerprint = (uint32_t)(seed ^ (seed >> 32));
	int i;
	uint8_t k[8];
	for (i=0;i<8;i++) {
		k[i] = seed & 0xff;
		seed >>= 8;
	}
	for (i=0;i<256;i++) {
		rs->sbox[i] = (uint8_t)((i + k[i%8]) & 0xff);
	}
	return rs->fingerprint;
}

uint32_t
rc4_encode(struct rc4_sbox *rs, const uint8_t *src, uint8_t *des, size_t sz) {
	size_t i;
	for (i=0;i<sz;i++) {
		rs->i = (rs->i + 1) % 256;
		rs->j = (rs->j + rs->sbox[rs->i]) % 256;
		uint8_t si = rs->sbox[rs->i];
		uint8_t sj = rs->sbox[rs->j];
		rs->sbox[rs->i] = sj;
		rs->sbox[rs->j] = si;
		uint8_t d = src[i] ^ rs->sbox[(si+sj) % 256];
		des[i] = d;
		
		rs->fingerprint = LEFTROTATE(rs->fingerprint , 4) ^ d;
	}
	return rs->fingerprint;
}
