/* $Id: MD5.xs,v 1.23 1999/03/26 13:27:49 gisle Exp $ */
#ifdef __cplusplus
extern "C" {
#endif
#include "EXTERN.h"
#include "perl.h"
#include "md5.h"
#ifdef __cplusplus
}
#endif

void
MD5Init(MD5_CTX *ctx)
{
  /* Start state */
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;

  /* message length */
  ctx->bytes_low = ctx->bytes_high = 0;
}

/* Padding is added at the end of the message in order to fill a
 * complete 64 byte block (- 8 bytes for the message length).  The
 * padding is also the reason the buffer in MD5_CTX have to be
 * 128 bytes.
 */
static unsigned char PADDING[64] = {
  0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

static void
MD5Transform(MD5_CTX* ctx, const U8* buf, STRLEN blocks)
{
/*    static int tcount = 0; */

    U32 A = ctx->A;
    U32 B = ctx->B;
    U32 C = ctx->C;
    U32 D = ctx->D;

#ifndef U32_ALIGNMENT_REQUIRED
    const U32 *x = (U32*)buf;  /* really just type casting */
#endif

    do {
	U32 a = A;
	U32 b = B;
	U32 c = C;
	U32 d = D;

#if BYTEORDER == 0x1234 && !defined(U32_ALIGNMENT_REQUIRED)
	const U32 *X = x;
        #define NEXTx  (*x++)
#else
	U32 X[16];      /* converted values, used in round 2-4 */
	U32 *uptr = X;
	U32 tmp;
 #ifdef BYTESWAP
        #define NEXTx  (tmp=*x++, *uptr++ = BYTESWAP(tmp))
 #else
        #define NEXTx  (s2u(buf,tmp), buf += 4, *uptr++ = tmp)
 #endif
#endif

	/* Round 1 */
	FF (a, b, c, d, S11, 0xd76aa478); /* 1 */
	FF (d, a, b, c, S12, 0xe8c7b756); /* 2 */
	FF (c, d, a, b, S13, 0x242070db); /* 3 */
	FF (b, c, d, a, S14, 0xc1bdceee); /* 4 */
	FF (a, b, c, d, S11, 0xf57c0faf); /* 5 */
	FF (d, a, b, c, S12, 0x4787c62a); /* 6 */
	FF (c, d, a, b, S13, 0xa8304613); /* 7 */
	FF (b, c, d, a, S14, 0xfd469501); /* 8 */
	FF (a, b, c, d, S11, 0x698098d8); /* 9 */
	FF (d, a, b, c, S12, 0x8b44f7af); /* 10 */
	FF (c, d, a, b, S13, 0xffff5bb1); /* 11 */
	FF (b, c, d, a, S14, 0x895cd7be); /* 12 */
	FF (a, b, c, d, S11, 0x6b901122); /* 13 */
	FF (d, a, b, c, S12, 0xfd987193); /* 14 */
	FF (c, d, a, b, S13, 0xa679438e); /* 15 */
	FF (b, c, d, a, S14, 0x49b40821); /* 16 */

	/* Round 2 */
	GG (a, b, c, d,  1, S21, 0xf61e2562); /* 17 */
	GG (d, a, b, c,  6, S22, 0xc040b340); /* 18 */
	GG (c, d, a, b, 11, S23, 0x265e5a51); /* 19 */
	GG (b, c, d, a,  0, S24, 0xe9b6c7aa); /* 20 */
	GG (a, b, c, d,  5, S21, 0xd62f105d); /* 21 */
	GG (d, a, b, c, 10, S22,  0x2441453); /* 22 */
	GG (c, d, a, b, 15, S23, 0xd8a1e681); /* 23 */
	GG (b, c, d, a,  4, S24, 0xe7d3fbc8); /* 24 */
	GG (a, b, c, d,  9, S21, 0x21e1cde6); /* 25 */
	GG (d, a, b, c, 14, S22, 0xc33707d6); /* 26 */
	GG (c, d, a, b,  3, S23, 0xf4d50d87); /* 27 */
	GG (b, c, d, a,  8, S24, 0x455a14ed); /* 28 */
	GG (a, b, c, d, 13, S21, 0xa9e3e905); /* 29 */
	GG (d, a, b, c,  2, S22, 0xfcefa3f8); /* 30 */
	GG (c, d, a, b,  7, S23, 0x676f02d9); /* 31 */
	GG (b, c, d, a, 12, S24, 0x8d2a4c8a); /* 32 */

	/* Round 3 */
	HH (a, b, c, d,  5, S31, 0xfffa3942); /* 33 */
	HH (d, a, b, c,  8, S32, 0x8771f681); /* 34 */
	HH (c, d, a, b, 11, S33, 0x6d9d6122); /* 35 */
	HH (b, c, d, a, 14, S34, 0xfde5380c); /* 36 */
	HH (a, b, c, d,  1, S31, 0xa4beea44); /* 37 */
	HH (d, a, b, c,  4, S32, 0x4bdecfa9); /* 38 */
	HH (c, d, a, b,  7, S33, 0xf6bb4b60); /* 39 */
	HH (b, c, d, a, 10, S34, 0xbebfbc70); /* 40 */
	HH (a, b, c, d, 13, S31, 0x289b7ec6); /* 41 */
	HH (d, a, b, c,  0, S32, 0xeaa127fa); /* 42 */
	HH (c, d, a, b,  3, S33, 0xd4ef3085); /* 43 */
	HH (b, c, d, a,  6, S34,  0x4881d05); /* 44 */
	HH (a, b, c, d,  9, S31, 0xd9d4d039); /* 45 */
	HH (d, a, b, c, 12, S32, 0xe6db99e5); /* 46 */
	HH (c, d, a, b, 15, S33, 0x1fa27cf8); /* 47 */
	HH (b, c, d, a,  2, S34, 0xc4ac5665); /* 48 */

	/* Round 4 */
	II (a, b, c, d,  0, S41, 0xf4292244); /* 49 */
	II (d, a, b, c,  7, S42, 0x432aff97); /* 50 */
	II (c, d, a, b, 14, S43, 0xab9423a7); /* 51 */
	II (b, c, d, a,  5, S44, 0xfc93a039); /* 52 */
	II (a, b, c, d, 12, S41, 0x655b59c3); /* 53 */
	II (d, a, b, c,  3, S42, 0x8f0ccc92); /* 54 */
	II (c, d, a, b, 10, S43, 0xffeff47d); /* 55 */
	II (b, c, d, a,  1, S44, 0x85845dd1); /* 56 */
	II (a, b, c, d,  8, S41, 0x6fa87e4f); /* 57 */
	II (d, a, b, c, 15, S42, 0xfe2ce6e0); /* 58 */
	II (c, d, a, b,  6, S43, 0xa3014314); /* 59 */
	II (b, c, d, a, 13, S44, 0x4e0811a1); /* 60 */
	II (a, b, c, d,  4, S41, 0xf7537e82); /* 61 */
	II (d, a, b, c, 11, S42, 0xbd3af235); /* 62 */
	II (c, d, a, b,  2, S43, 0x2ad7d2bb); /* 63 */
	II (b, c, d, a,  9, S44, 0xeb86d391); /* 64 */

	A += a;  TRUNC32(A);
	B += b;  TRUNC32(B);
	C += c;  TRUNC32(C);
	D += d;  TRUNC32(D);

    } while (--blocks);
    ctx->A = A;
    ctx->B = B;
    ctx->C = C;
    ctx->D = D;
}

void
MD5Final(U8* digest, MD5_CTX *ctx)
{
    STRLEN fill = ctx->bytes_low & 0x3F;
    STRLEN padlen = (fill < 56 ? 56 : 120) - fill;
    U32 bits_low, bits_high;
    Copy(PADDING, ctx->buffer + fill, padlen, U8);
    fill += padlen;
    bits_low = ctx->bytes_low << 3;
    bits_high = (ctx->bytes_high << 3) | (ctx->bytes_low  >> 29);
#ifdef BYTESWAP
    *(U32*)(ctx->buffer + fill) = BYTESWAP(bits_low);    fill += 4;
    *(U32*)(ctx->buffer + fill) = BYTESWAP(bits_high);   fill += 4;
#else
    u2s(bits_low,  ctx->buffer + fill);   fill += 4;
    u2s(bits_high, ctx->buffer + fill);   fill += 4;
#endif

    MD5Transform(ctx, ctx->buffer, fill >> 6);
#ifdef BYTESWAP
    *(U32*)digest = BYTESWAP(ctx->A);  digest += 4;
    *(U32*)digest = BYTESWAP(ctx->B);  digest += 4;
    *(U32*)digest = BYTESWAP(ctx->C);  digest += 4;
    *(U32*)digest = BYTESWAP(ctx->D);
#else
    u2s(ctx->A, digest);
    u2s(ctx->B, digest+4);
    u2s(ctx->C, digest+8);
    u2s(ctx->D, digest+12);
#endif
}

void
MD5Update(MD5_CTX* ctx, const U8* buf, STRLEN len)
{
    STRLEN blocks;
    STRLEN fill = ctx->bytes_low & 0x3F;
    ctx->bytes_low += len;
    if (ctx->bytes_low < len) /* wrap around */
	ctx->bytes_high++;

    if (fill) {
	STRLEN missing = 64 - fill;
	if (len < missing) {
	    Copy(buf, ctx->buffer + fill, len, U8);
	    return;
	}
	Copy(buf, ctx->buffer + fill, missing, U8);
	MD5Transform(ctx, ctx->buffer, 1);
	buf += missing;
	len -= missing;
    }

    blocks = len >> 6;
    if (blocks)
	MD5Transform(ctx, buf, blocks);
    if ( (len &= 0x3F)) {
	Copy(buf + (blocks << 6), ctx->buffer, len, U8);
    }
}

/* conversion for 16 character binary md5 to hex */

unsigned char * 
hex_16(unsigned char* from, unsigned char* to)
{
    static char *hexdigits = "0123456789abcdef";
    const unsigned char *end = from + 16;
    char *d = to;

    while (from < end) {
	*d++ = hexdigits[(*from >> 4)];
	*d++ = hexdigits[(*from & 0x0F)];
	from++;
    }
    *d = '\0';
    return to;
}

/* conversion for 16 character binary md5 to base64 */

unsigned char *
base64_16(unsigned char* from, unsigned char* to)
{
    static char* base64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const unsigned char *end = from + 16;
    unsigned char c1, c2, c3;
    char *d = to;

    while (1) {
        c1 = *from++;
        *d++ = base64[c1>>2];
        if (from == end) {
            *d++ = base64[(c1 & 0x3) << 4];
            break;
        }
        c2 = *from++;
        c3 = *from++;
        *d++ = base64[((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4)];
        *d++ = base64[((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)];
        *d++ = base64[c3 & 0x3F];
    }
    *d = '\0';
    return to;   
}                
