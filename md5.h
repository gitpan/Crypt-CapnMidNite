/* Perl does not guarantee that U32 is exactly 32 bits.  Some system
 * has no integral type with exactly 32 bits.  For instance, A Cray has
 * short, int and long all at 64 bits so we need to apply this macro
 * to reduce U32 values to 32 bits at appropriate places. If U32
 * really does have 32 bits then this is a no-op.
 */
#if BYTEORDER > 0x4321 || defined(TRUNCATE_U32)
  #define TO32(x)    ((x) &  0xFFFFffff)
  #define TRUNC32(x) ((x) &= 0xFFFFffff)
#else
  #define TO32(x)    (x)
  #define TRUNC32(x) /*nothing*/
#endif

/* The MD5 algorithm is defined in terms of little endian 32-bit
 * values.  The following macros (and functions) allow us to convert
 * between native integers and such values.
 */
#undef BYTESWAP
#ifndef U32_ALIGNMENT_REQUIRED
 #if BYTEORDER == 0x1234      /* 32-bit little endian */
  #define BYTESWAP(x) (x)     /* no-op */

 #elif BYTEORDER == 0x4321    /* 32-bit big endian */
  #define BYTESWAP(x) 	((((x)&0xFF)<<24)	\
			|(((x)>>24)&0xFF)	\
			|(((x)&0x0000FF00)<<8)	\
			|(((x)&0x00FF0000)>>8)	)
 #endif
#endif
#ifndef BYTESWAP
static void u2s(U32 u, U8* s)
{
    *s++ = u         & 0xFF;
    *s++ = (u >>  8) & 0xFF;
    *s++ = (u >> 16) & 0xFF;
    *s   = (u >> 24) & 0xFF;
}

#define s2u(s,u) ((u) =  (U32)(*s)            |  \
                        ((U32)(*(s+1)) << 8)  |  \
                        ((U32)(*(s+2)) << 16) |  \
                        ((U32)(*(s+3)) << 24))
#endif

/* This stucture keeps the current state of algorithm.
 */
typedef struct {
  U32 A, B, C, D;  /* current digest */
  U32 bytes_low;   /* counts bytes in message */
  U32 bytes_high;  /* turn it into a 64-bit counter */
  U8 buffer[128];  /* collect complete 64 byte blocks */
} MD5_CTX;


/* Constants for MD5Transform routine.
 */
#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & ((y) ^ (z)) ^ (z)))
#define G(x, y, z) F(z, x, y)
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n) | ((x) >> (32-(n)))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
 * Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, s, ac)                    \
 (a) += F ((b), (c), (d)) + (NEXTx) + (U32)(ac); \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));

#define GG(a, b, c, d, x, s, ac)                 \
 (a) += G ((b), (c), (d)) + X[x] + (U32)(ac);    \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));

#define HH(a, b, c, d, x, s, ac)                 \
 (a) += H ((b), (c), (d)) + X[x] + (U32)(ac);    \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));

#define II(a, b, c, d, x, s, ac)                 \
 (a) += I ((b), (c), (d)) + X[x] + (U32)(ac);    \
 TRUNC32((a));                                   \
 (a) = ROTATE_LEFT ((a), (s));                   \
 (a) += (b);                                     \
 TRUNC32((a));


/* Formats */
#define F_BIN 0
#define F_HEX 1
#define F_B64 2

void MD5Init(MD5_CTX *ctx);
void MD5Final(U8* digest, MD5_CTX *ctx);
void MD5Update(MD5_CTX* ctx, const U8* buf, STRLEN len);
unsigned char * hex_16(unsigned char * from, unsigned char * to);
unsigned char * base64_16(unsigned char * from, unsigned char * to);
