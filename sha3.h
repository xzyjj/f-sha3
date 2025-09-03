/* sha3.h - secure hash-3 algorithm definitions */

#ifndef SHA3_H
#define SHA3_H

#include <stdint.h>


/* @def: sha3 */
#undef SHA3_224_TYPE
#define SHA3_224_TYPE 1
#undef SHA3_224_LEN
#define SHA3_224_LEN 28
/* (1600 - (2 * 224)) / 8 */
#undef SHA3_224_RATE
#define SHA3_224_RATE 144

#undef SHA3_256_TYPE
#define SHA3_256_TYPE 2
#undef SHA3_256_LEN
#define SHA3_256_LEN 32
/* (1600 - (2 * 256)) / 8 */
#undef SHA3_256_RATE
#define SHA3_256_RATE 136

#undef SHA3_384_TYPE
#define SHA3_384_TYPE 3
#undef SHA3_384_LEN
#define SHA3_384_LEN 48
/* (1600 - (2 * 384)) / 8 */
#undef SHA3_384_RATE
#define SHA3_384_RATE 104

#undef SHA3_512_TYPE
#define SHA3_512_TYPE 4
#undef SHA3_512_LEN
#define SHA3_512_LEN 64
/* (1600 - (2 * 512)) / 8 */
#undef SHA3_512_RATE
#define SHA3_512_RATE 72

#undef SHA3_SHAKE128_TYPE
#define SHA3_SHAKE128_TYPE 5
/* (1600 - (2 * 128)) / 8 */
#undef SHA3_SHAKE128_RATE
#define SHA3_SHAKE128_RATE 168

#undef SHA3_SHAKE256_TYPE
#define SHA3_SHAKE256_TYPE 6
/* (1600 - (2 * 256)) / 8 */
#undef SHA3_SHAKE256_RATE
#define SHA3_SHAKE256_RATE 136

#undef SHA3_STATE_SIZE
#define SHA3_STATE_SIZE (5 * 5 * 8)
#undef SHA3_KECCAK_ROUNDS
#define SHA3_KECCAK_ROUNDS 24

#undef sha3_ctx
struct sha3_ctx {
	uint64_t state[5][5];
	union {
		uint8_t buf[SHA3_STATE_SIZE];
		uint8_t digest[SHA3_STATE_SIZE];
	} u;
	uint8_t pad;
	uint32_t rate;
	uint32_t dsize;
	uint32_t count;
};

#undef SHA3_NEW
#define SHA3_NEW(x) struct sha3_ctx x

#undef SHA3_SETPAD
#define SHA3_SETPAD(x) ((x)->pad)
#undef SHA3_GETDSIZE
#define SHA3_GETDSIZE(x) ((x)->dsize)
#undef SHA3_GETRATE
#define SHA3_GETRATE(x) ((x)->rate)
#undef SHA3_STATE
#define SHA3_STATE(x, n) ((x)->u.digest[n])
/* end */

#ifdef __cplusplus
extern "C" {
#endif

/* sha3.c */
extern int32_t sha3_init(struct sha3_ctx *ctx, int32_t type, uint32_t dsize);
extern void sha3_process(struct sha3_ctx *ctx, const uint8_t *s,
		uint64_t len);
extern void sha3_finish(struct sha3_ctx *ctx);
extern void sha3(struct sha3_ctx *ctx, const uint8_t *s, uint64_t len);

#ifdef __cplusplus
}
#endif


#endif
