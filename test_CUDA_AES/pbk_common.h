/*
 * pbk_common.h
 *
 *  Created on: 21 Feb, 2017
 *      Author: cg
 */

#ifndef PBK_COMMON_H_
#define PBK_COMMON_H_

#define IPAD 0x36363636
#define OPAD 0x5c5c5c5c


#include <stdint.h>

# define SWAP(n)							\
  (n >> 24) |((n << 8) & 0x00FF0000) | ((n >> 8) & 0x0000FF00) | (n << 24)

#define BLOCK_DIM 32
#define TEST_SIZE 4096

/* Structure to save state of computation between the single steps.  */
struct sha1_ctx
{
  uint32_t A;
  uint32_t B;
  uint32_t C;
  uint32_t D;
  uint32_t E;

  uint32_t total[2];
  uint32_t buflen;
  uint32_t buffer[32];
};


struct globalChars {
  char block[64];
  char innerhash[20];
};

__device__ void sha1_process_block (const void *buffer, size_t len,
				    struct sha1_ctx * ctx);

__device__ void
cudaMemcpyDevice(void * dst, const void * src, size_t len) {
  int rest = len%4;
  len=len/4;
  char *d2 = (char*) dst+4*len;
  const char *s2 = (char *) src+4*len;
  int *d = (int *) dst;
  const int *s = (int *) src;
  for (size_t i=0; i<len; i++) {
    d[i] = s[i];
  }
  for (size_t i=0; i<rest; i++) {
    d2[i] = s2[i];
  }
}

__device__ void
cudaMemsetDevice ( void * ptr, uint32_t value, size_t num ) {
  int rest = num%4;
  num = num/4;
  uint32_t *d = (uint32_t *) ptr;
  for (size_t i = 0; i < num; i++) {
    d[i] = value;
  }
  uint8_t *d2 = (uint8_t*) ptr+num*4;
  uint8_t v = value;
  for (size_t i = 0; i < rest; i++)
    d2[i] = v;
}


/* Take a pointer to a 160 bit block of data (five 32 bit ints) and
   initialize it to the start constants of the SHA1 algorithm.  This
   must be called before using hash in the call to sha1_hash.  */
__device__ void
sha1_init_ctx (struct sha1_ctx * ctx)
{
  ctx->A = 0x67452301;
  ctx->B = 0xefcdab89;
  ctx->C = 0x98badcfe;
  ctx->D = 0x10325476;
  ctx->E = 0xc3d2e1f0;

  ctx->total[0] = ctx->total[1] = 0;
  ctx->buflen = 0;
}

/* Copy the 4 byte value from v into the memory location pointed to by *cp,
   If your architecture allows unaligned access this is equivalent to
   * (uint32_t *) cp = v  */
__forceinline__ __device__ void
set_uint32 (char *cp, uint32_t v)
{
  cudaMemcpyDevice (cp, &v, sizeof v);
}

/* Put result from CTX in first 20 bytes following RESBUF.  The result
   must be in little endian byte order.  */
__device__ void
sha1_read_ctx (const struct sha1_ctx * ctx, void *resbuf)
{
  char *r = (char *) resbuf;
  set_uint32 (r + 0 * sizeof ctx->A, SWAP (ctx->A));
  set_uint32 (r + 1 * sizeof ctx->B, SWAP (ctx->B));
  set_uint32 (r + 2 * sizeof ctx->C, SWAP (ctx->C));
  set_uint32 (r + 3 * sizeof ctx->D, SWAP (ctx->D));
  set_uint32 (r + 4 * sizeof ctx->E, SWAP (ctx->E));
}

/* Process the remaining bytes in the internal buffer and the usual
   prolog according to the standard and write the result to RESBUF.  */
__device__ void
sha1_finish_ctx (struct sha1_ctx *ctx, void *resbuf)
{
  // Take yet unprocessed bytes into account.
  size_t bytes = ctx->buflen;
  size_t size = (bytes < 56) ? 64 / 4 : 64 * 2 / 4;

  // Now count remaining bytes.
  ctx->total[0] += bytes;
  if (ctx->total[0] < bytes)
    ++ctx->total[1];

  // Put the 64-bit file length in *bits* at the end of the buffer.
  ctx->buffer[size - 2] = SWAP ((ctx->total[1] << 3) | (ctx->total[0] >> 29));
  ctx->buffer[size - 1] = SWAP (ctx->total[0] << 3);

  ((int *)ctx->buffer)[bytes/4] = 0x00000080;
  cudaMemsetDevice(&((char *)ctx->buffer)[bytes+4], 0, (size - 2) * 4 - bytes-4);

  // Process last bytes.
  sha1_process_block (ctx->buffer, size * 4, ctx);

  sha1_read_ctx (ctx, resbuf);
}

__device__ void
sha1_process_bytes (const void *buffer, size_t len, struct sha1_ctx * ctx)
{
  /* When we already have some bits in our internal buffer concatenate
     both inputs first.  */
  if (ctx->buflen != 0)
    {
      size_t left_over = ctx->buflen;
      size_t add = 128 - left_over > len ? len : 128 - left_over;

      cudaMemcpyDevice (&((char *) ctx->buffer)[left_over], buffer, add);
      ctx->buflen += add;

      if (ctx->buflen > 64)
        {
          sha1_process_block (ctx->buffer, ctx->buflen & ~63, ctx);

          ctx->buflen &= 63;
          /* The regions in the following copy operation cannot overlap.  */
          cudaMemcpyDevice (ctx->buffer,
			    &((char *) ctx->buffer)[(left_over + add) & ~63],
			    ctx->buflen);
        }

      buffer = (const char *) buffer + add;
      len -= add;
    }

  /* Process available complete blocks.  */
  if (len >= 64)
    {
      sha1_process_block (buffer, len & ~63, ctx);
      buffer = (const char *) buffer + (len & ~63);
      len &= 63;
    }

  /* Move remaining bytes in internal buffer.  */
  if (len > 0)
    {
      size_t  left_over = ctx->buflen;

      cudaMemcpyDevice (&((char *) ctx->buffer)[left_over], buffer, len);
      left_over += len;
      if (left_over >= 64)
        {
          sha1_process_block (ctx->buffer, 64, ctx);
          left_over -= 64;
          cudaMemcpyDevice (ctx->buffer, &ctx->buffer[16], left_over);
	}
      ctx->buflen = left_over;
    }
}

/* SHA1 round constants */
#define K1 0x5a827999
#define K2 0x6ed9eba1
#define K3 0x8f1bbcdc
#define K4 0xca62c1d6

/* Round functions.  Note that F2 is the same as F4.  */
#define F1(B,C,D) ( D ^ ( B & ( C ^ D ) ) )
#define F2(B,C,D) (B ^ C ^ D)
#define F3(B,C,D) ( ( B & C ) | ( D & ( B | C ) ) )
#define F4(B,C,D) (B ^ C ^ D)

/* Process LEN bytes of BUFFER, accumulating context into CTX.
   It is assumed that LEN % 64 == 0.
   Most of this code comes from GnuPG's cipher/sha1.c.  */

__device__ void
sha1_process_block (const void *buffer, size_t len, struct sha1_ctx *ctx)
{
  const uint32_t *words = (const uint32_t *) buffer;
  size_t nwords = len / sizeof (uint32_t);
  const uint32_t *endp = words + nwords;
  uint32_t x[16];

  uint32_t a = ctx->A;
  uint32_t b = ctx->B;
  uint32_t c = ctx->C;
  uint32_t d = ctx->D;
  uint32_t e = ctx->E;

  /* First increment the byte count.  RFC 1321 specifies the possible
     length of the file up to 2^64 bits.  Here we only compute the
     number of bytes.  Do a double word increment.  */
  ctx->total[0] += len;
  if (ctx->total[0] < len)
    ++ctx->total[1];

#define rol(y, n) (((y) << (n)) | ((uint32_t) (y) >> (32 - (n))))

#define M(I) ( tm =   x[I&0x0f] ^ x[(I-14)&0x0f]	\
	       ^ x[(I-8)&0x0f] ^ x[(I-3)&0x0f]		\
	       , (x[I&0x0f] = rol(tm, 1)) )

#define R(A,B,C,D,E,F,K,M)  do { E += rol( A, 5 )	\
      + F( B, C, D )					\
      + K						\
      + M;						\
    B = rol( B, 30 );					\
  } while(0)
  uint32_t tm;
  size_t t;
  while (words < endp)
    {
      for (t = 0; t < 16; t++)
        {
          x[t]= SWAP (*words);
          words++;
        }

      R( a, b, c, d, e, F1, K1, x[ 0] );
      R( e, a, b, c, d, F1, K1, x[ 1] );
      R( d, e, a, b, c, F1, K1, x[ 2] );
      R( c, d, e, a, b, F1, K1, x[ 3] );
      R( b, c, d, e, a, F1, K1, x[ 4] );
      R( a, b, c, d, e, F1, K1, x[ 5] );
      R( e, a, b, c, d, F1, K1, x[ 6] );
      R( d, e, a, b, c, F1, K1, x[ 7] );
      R( c, d, e, a, b, F1, K1, x[ 8] );
      R( b, c, d, e, a, F1, K1, x[ 9] );
      R( a, b, c, d, e, F1, K1, x[10] );
      R( e, a, b, c, d, F1, K1, x[11] );
      R( d, e, a, b, c, F1, K1, x[12] );
      R( c, d, e, a, b, F1, K1, x[13] );
      R( b, c, d, e, a, F1, K1, x[14] );
      R( a, b, c, d, e, F1, K1, x[15] );
      R( e, a, b, c, d, F1, K1, M(16) );
      R( d, e, a, b, c, F1, K1, M(17) );
      R( c, d, e, a, b, F1, K1, M(18) );
      R( b, c, d, e, a, F1, K1, M(19) );
      R( a, b, c, d, e, F2, K2, M(20) );
      R( e, a, b, c, d, F2, K2, M(21) );
      R( d, e, a, b, c, F2, K2, M(22) );
      R( c, d, e, a, b, F2, K2, M(23) );
      R( b, c, d, e, a, F2, K2, M(24) );
      R( a, b, c, d, e, F2, K2, M(25) );
      R( e, a, b, c, d, F2, K2, M(26) );
      R( d, e, a, b, c, F2, K2, M(27) );
      R( c, d, e, a, b, F2, K2, M(28) );
      R( b, c, d, e, a, F2, K2, M(29) );
      R( a, b, c, d, e, F2, K2, M(30) );
      R( e, a, b, c, d, F2, K2, M(31) );
      R( d, e, a, b, c, F2, K2, M(32) );
      R( c, d, e, a, b, F2, K2, M(33) );
      R( b, c, d, e, a, F2, K2, M(34) );
      R( a, b, c, d, e, F2, K2, M(35) );
      R( e, a, b, c, d, F2, K2, M(36) );
      R( d, e, a, b, c, F2, K2, M(37) );
      R( c, d, e, a, b, F2, K2, M(38) );
      R( b, c, d, e, a, F2, K2, M(39) );
      R( a, b, c, d, e, F3, K3, M(40) );
      R( e, a, b, c, d, F3, K3, M(41) );
      R( d, e, a, b, c, F3, K3, M(42) );
      R( c, d, e, a, b, F3, K3, M(43) );
      R( b, c, d, e, a, F3, K3, M(44) );
      R( a, b, c, d, e, F3, K3, M(45) );
      R( e, a, b, c, d, F3, K3, M(46) );
      R( d, e, a, b, c, F3, K3, M(47) );
      R( c, d, e, a, b, F3, K3, M(48) );
      R( b, c, d, e, a, F3, K3, M(49) );
      R( a, b, c, d, e, F3, K3, M(50) );
      R( e, a, b, c, d, F3, K3, M(51) );
      R( d, e, a, b, c, F3, K3, M(52) );
      R( c, d, e, a, b, F3, K3, M(53) );
      R( b, c, d, e, a, F3, K3, M(54) );
      R( a, b, c, d, e, F3, K3, M(55) );
      R( e, a, b, c, d, F3, K3, M(56) );
      R( d, e, a, b, c, F3, K3, M(57) );
      R( c, d, e, a, b, F3, K3, M(58) );
      R( b, c, d, e, a, F3, K3, M(59) );
      R( a, b, c, d, e, F4, K4, M(60) );
      R( e, a, b, c, d, F4, K4, M(61) );
      R( d, e, a, b, c, F4, K4, M(62) );
      R( c, d, e, a, b, F4, K4, M(63) );
      R( b, c, d, e, a, F4, K4, M(64) );
      R( a, b, c, d, e, F4, K4, M(65) );
      R( e, a, b, c, d, F4, K4, M(66) );
      R( d, e, a, b, c, F4, K4, M(67) );
      R( c, d, e, a, b, F4, K4, M(68) );
      R( b, c, d, e, a, F4, K4, M(69) );
      R( a, b, c, d, e, F4, K4, M(70) );
      R( e, a, b, c, d, F4, K4, M(71) );
      R( d, e, a, b, c, F4, K4, M(72) );
      R( c, d, e, a, b, F4, K4, M(73) );
      R( b, c, d, e, a, F4, K4, M(74) );
      R( a, b, c, d, e, F4, K4, M(75) );
      R( e, a, b, c, d, F4, K4, M(76) );
      R( d, e, a, b, c, F4, K4, M(77) );
      R( c, d, e, a, b, F4, K4, M(78) );
      R( b, c, d, e, a, F4, K4, M(79) );

      a = ctx->A += a;
      b = ctx->B += b;
      c = ctx->C += c;
      d = ctx->D += d;
      e = ctx->E += e;
    }
}

__device__ void
memxor (void * dest, const void * src,size_t n)
{
  int rest = n%4;
  n = n/4;
  const int * s = (int*)src;
  int *d = (int*)dest;
  const char * s2 = (char*)src+4*n;
  char *d2 = (char*)dest+4*n;
  for (; n > 0; n--)
    *d++ ^= *s++;
  for (; rest > 0; rest--)
    *d2++ ^= *s2++;
}
__device__ void
hmac_sha1 (const void * key, uint32_t keylen,
           const void *in, uint32_t inlen, void *resbuf, struct globalChars *chars)
{
  struct sha1_ctx inner;
  struct sha1_ctx outer;

  sha1_init_ctx (&inner);
  cudaMemsetDevice (chars->block, IPAD, sizeof (chars->block));
  memxor(chars->block, key, keylen);
  sha1_process_block (chars->block, 64, &inner);
  sha1_process_bytes (in, inlen, &inner);
  sha1_finish_ctx (&inner, chars->innerhash);

  /* Compute result from KEY and INNERHASH.  */
  sha1_init_ctx (&outer);
  cudaMemsetDevice (chars->block, OPAD, sizeof (chars->block));
  memxor(chars->block, key, keylen);
  sha1_process_block (chars->block, 64, &outer);
  sha1_process_bytes (chars->innerhash, 20, &outer);
  sha1_finish_ctx (&outer, resbuf);
}







#endif /* PBK_COMMON_H_ */
