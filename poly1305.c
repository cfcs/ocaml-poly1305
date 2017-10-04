#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <endian.h>

#define CAML_NAME_SPACE
#include <caml/mlvalues.h>
#include <caml/bigarray.h>

// this is some sort of GCC hint thingie... disabling that.
#define likely(b) (b)
#define unlikely(b) (b)
# define __always_inline __inline __attribute__ ((__always_inline__))

// define type aliases
typedef uint8_t u8;
typedef unsigned char u_char;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef u32 __le32;
typedef u32 __u32;

unsigned int min(unsigned int a, unsigned int b)
{
  return (a<b ? a : b);
}

//copy-paste from include/linux/unaligned/little_endian.h
static inline u16 get_unaligned_le16(const u8 *p)
{
  return (u16)(p[0] | p[1] << 8);
}

static inline u32 get_unaligned_le32(const u8 *p)
{
  return (u32)(p[0] | p[1] << 8 | p[2] << 16 | p[3] << 24);
}

/////// can't figure out how to include this: #include <asm/byteorder.h>
/////// copy-paste from little_endian.h:
#define __le32_to_cpu(x) ((__u32)(__le32)(x))
static __always_inline __u32 __le32_to_cpup(const __le32 *p)
{
        return (__u32)*p;
}
#define __cpu_to_le32(x) ((__le32)(__u32)(x))
#define cpu_to_le32(x) __cpu_to_le32(x)

#define le32_to_cpuvp(p) __le32_to_cpup((const void*) p)

////////////////////////////// end of kernel copy-paste compatibility

static inline u64 mlt(u64 a, u64 b)
{
	return a * b;
}

static inline u32 sr(u64 v, u_char n)
{
	return v >> n;
}

static inline u32 and(u32 v, u32 mask)
{
	return v & mask;
}

enum poly1305_constants {
  POLY1305_BLOCK_SIZE = 16,
  POLY1305_KEY_SIZE   = 32,
  POLY1305_MAC_SIZE   = 16,
};

struct poly1305_ctx {
	/* key */
	u32 r[5];
	/* finalize key */
	u32 s[4];
	/* accumulator */
	u32 h[5];
	/* partial buffer */
	u8 buf[POLY1305_BLOCK_SIZE];
	/* bytes used in partial buffer */
	unsigned int buflen;
	/* derived key u set? */
	bool uset;
	/* derived keys r^3, r^4 set? */
	bool wset;
	/* derived Poly1305 key r^2 */
	u32 u[5];
	/* derived Poly1305 key r^3 */
	u32 r3[5];
	/* derived Poly1305 key r^4 */
	u32 r4[5];
};

CAMLprim value
caml_poly1305_sizeof_ctx(value x)
{
    return Val_int(sizeof(struct poly1305_ctx));
}

static void
poly1305_init(struct poly1305_ctx *ctx, const u8 key[POLY1305_KEY_SIZE])
{
    memset(ctx, 0, sizeof(struct poly1305_ctx));
    /* r &= 0xffffffc0ffffffc0ffffffc0fffffff */
    ctx->r[0] = (le32_to_cpuvp(key +  0) >> 0) & 0x3ffffff;
    ctx->r[1] = (get_unaligned_le32(key +  3) >> 2) & 0x3ffff03;
    ctx->r[2] = (get_unaligned_le32(key +  6) >> 4) & 0x3ffc0ff;
    ctx->r[3] = (get_unaligned_le32(key +  9) >> 6) & 0x3f03fff;
    ctx->r[4] = (le32_to_cpuvp(key + 12) >> 8) & 0x00fffff;
    ctx->s[0] = le32_to_cpuvp(key +  16);
    ctx->s[1] = le32_to_cpuvp(key +  20);
    ctx->s[2] = le32_to_cpuvp(key +  24);
    ctx->s[3] = le32_to_cpuvp(key +  28);
}

CAMLprim value
caml_poly1305_init(value ctx, value ctx_offset,
		   value key, value key_offset)
{
  // TODO check size of ctx; key
  poly1305_init( Caml_ba_data_val(ctx) + Unsigned_long_val(ctx_offset),
		 Caml_ba_data_val(key) + Unsigned_long_val(key_offset));
  return Val_unit;
}

static unsigned
int poly1305_generic_blocks(struct poly1305_ctx *ctx, const u8 *src, unsigned int srclen, u32 hibit)
{
	u32 r0, r1, r2, r3, r4;
	u32 s1, s2, s3, s4;
	u32 h0, h1, h2, h3, h4;
	u64 d0, d1, d2, d3, d4;

	r0 = ctx->r[0];
	r1 = ctx->r[1];
	r2 = ctx->r[2];
	r3 = ctx->r[3];
	r4 = ctx->r[4];

	s1 = r1 * 5;
	s2 = r2 * 5;
	s3 = r3 * 5;
	s4 = r4 * 5;

	h0 = ctx->h[0];
	h1 = ctx->h[1];
	h2 = ctx->h[2];
	h3 = ctx->h[3];
	h4 = ctx->h[4];

	while (likely(srclen >= POLY1305_BLOCK_SIZE)) {
		/* h += m[i] */
		h0 += (le32_to_cpuvp(src +  0) >> 0) & 0x3ffffff;
		h1 += (get_unaligned_le32(src +  3) >> 2) & 0x3ffffff;
		h2 += (get_unaligned_le32(src +  6) >> 4) & 0x3ffffff;
		h3 += (get_unaligned_le32(src +  9) >> 6) & 0x3ffffff;
		h4 += (le32_to_cpuvp(src + 12) >> 8) | hibit;

		/* h *= r */
		d0 = mlt(h0, r0) + mlt(h1, s4) + mlt(h2, s3) + mlt(h3, s2) + mlt(h4, s1);
		d1 = mlt(h0, r1) + mlt(h1, r0) + mlt(h2, s4) + mlt(h3, s3) + mlt(h4, s2);
		d2 = mlt(h0, r2) + mlt(h1, r1) + mlt(h2, r0) + mlt(h3, s4) + mlt(h4, s3);
		d3 = mlt(h0, r3) + mlt(h1, r2) + mlt(h2, r1) + mlt(h3, r0) + mlt(h4, s4);
		d4 = mlt(h0, r4) + mlt(h1, r3) + mlt(h2, r2) + mlt(h3, r1) + mlt(h4, r0);

		/* (partial) h %= p */
		d1 += sr(d0, 26);     h0 = and(d0, 0x3ffffff);
		d2 += sr(d1, 26);     h1 = and(d1, 0x3ffffff);
		d3 += sr(d2, 26);     h2 = and(d2, 0x3ffffff);
		d4 += sr(d3, 26);     h3 = and(d3, 0x3ffffff);
		h0 += sr(d4, 26) * 5; h4 = and(d4, 0x3ffffff);
		h1 += h0 >> 26;       h0 = h0 & 0x3ffffff;

		src += POLY1305_BLOCK_SIZE;
		srclen -= POLY1305_BLOCK_SIZE;
	}

	ctx->h[0] = h0;
	ctx->h[1] = h1;
	ctx->h[2] = h2;
	ctx->h[3] = h3;
	ctx->h[4] = h4;

	return srclen;
}

static void poly1305_update(struct poly1305_ctx *ctx, const u8 *src, unsigned int srclen, bool have_simd)
{
	unsigned int bytes;

	if (unlikely(ctx->buflen)) {
		bytes = min(srclen, POLY1305_BLOCK_SIZE - ctx->buflen);
		memcpy(ctx->buf + ctx->buflen, src, bytes);
		src += bytes;
		srclen -= bytes;
		ctx->buflen += bytes;

		if (ctx->buflen == POLY1305_BLOCK_SIZE) {
#ifdef CONFIG_X86_64
			if (have_simd && chacha20poly1305_use_sse2)
				poly1305_simd_blocks(ctx, ctx->buf, POLY1305_BLOCK_SIZE);
			else
#endif
				poly1305_generic_blocks(ctx, ctx->buf, POLY1305_BLOCK_SIZE, 1 << 24);
			ctx->buflen = 0;
		}
	}

	if (likely(srclen >= POLY1305_BLOCK_SIZE)) {
#ifdef CONFIG_X86_64
		if (have_simd && chacha20poly1305_use_sse2)
			bytes = poly1305_simd_blocks(ctx, src, srclen);
		else
#endif
			bytes = poly1305_generic_blocks(ctx, src, srclen, 1 << 24);
		src += srclen - bytes;
		srclen = bytes;
	}

	if (unlikely(srclen)) {
		ctx->buflen = srclen;
		memcpy(ctx->buf, src, srclen);
	}
}

CAMLprim value
caml_poly1305_update(value ctx, value ctx_offset, value src, value offset, value length)
{
  bool have_simd = false;
  poly1305_update(Caml_ba_data_val(ctx) + Unsigned_long_val(ctx_offset),
		  Caml_ba_data_val(src) + Unsigned_long_val(offset),
                  Unsigned_long_val(length), have_simd);
  return Val_unit;
}

static void poly1305_finish(struct poly1305_ctx *ctx, u8 *dst)
{
	__le32 *mac = (__le32 *)dst;
	u32 h0, h1, h2, h3, h4;
	u32 g0, g1, g2, g3, g4;
	u32 mask;
	u64 f = 0;

	if (unlikely(ctx->buflen)) {
		ctx->buf[ctx->buflen++] = 1;
		memset(ctx->buf + ctx->buflen, 0, POLY1305_BLOCK_SIZE - ctx->buflen);
		poly1305_generic_blocks(ctx, ctx->buf, POLY1305_BLOCK_SIZE, 0);
	}

	/* fully carry h */
	h0 = ctx->h[0];
	h1 = ctx->h[1];
	h2 = ctx->h[2];
	h3 = ctx->h[3];
	h4 = ctx->h[4];

	h2 += (h1 >> 26);     h1 = h1 & 0x3ffffff;
	h3 += (h2 >> 26);     h2 = h2 & 0x3ffffff;
	h4 += (h3 >> 26);     h3 = h3 & 0x3ffffff;
	h0 += (h4 >> 26) * 5; h4 = h4 & 0x3ffffff;
	h1 += (h0 >> 26);     h0 = h0 & 0x3ffffff;

	/* compute h + -p */
	g0 = h0 + 5;
	g1 = h1 + (g0 >> 26);             g0 &= 0x3ffffff;
	g2 = h2 + (g1 >> 26);             g1 &= 0x3ffffff;
	g3 = h3 + (g2 >> 26);             g2 &= 0x3ffffff;
	g4 = h4 + (g3 >> 26) - (1 << 26); g3 &= 0x3ffffff;

	/* select h if h < p, or h + -p if h >= p */
	mask = (g4 >> ((sizeof(u32) * 8) - 1)) - 1;
	g0 &= mask;
	g1 &= mask;
	g2 &= mask;
	g3 &= mask;
	g4 &= mask;
	mask = ~mask;
	h0 = (h0 & mask) | g0;
	h1 = (h1 & mask) | g1;
	h2 = (h2 & mask) | g2;
	h3 = (h3 & mask) | g3;
	h4 = (h4 & mask) | g4;

	/* h = h % (2^128) */
	h0 = (h0 >>  0) | (h1 << 26);
	h1 = (h1 >>  6) | (h2 << 20);
	h2 = (h2 >> 12) | (h3 << 14);
	h3 = (h3 >> 18) | (h4 <<  8);

	/* mac = (h + s) % (2^128) */
	f = (f >> 32) + h0 + ctx->s[0]; mac[0] = cpu_to_le32(f);
	f = (f >> 32) + h1 + ctx->s[1]; mac[1] = cpu_to_le32(f);
	f = (f >> 32) + h2 + ctx->s[2]; mac[2] = cpu_to_le32(f);
	f = (f >> 32) + h3 + ctx->s[3]; mac[3] = cpu_to_le32(f);
}

CAMLprim value
caml_poly1305_finish(value ctx, value ctx_offset, value dst, value dst_offset)
{
  poly1305_finish(Caml_ba_data_val(ctx) + Unsigned_long_val(ctx_offset),
		  Caml_ba_data_val(dst) + Unsigned_long_val(dst_offset));
  return Val_unit;
}
