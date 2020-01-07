/* $OpenBSD: crypto_api.h,v 1.5 2019/01/21 10:20:12 djm Exp $ */

/*
 * Assembled from generated headers and source files by Markus Friedl.
 * Placed in the public domain.
 */

#ifndef crypto_api_h
#define crypto_api_h

#include <stdint.h>
#include <stdlib.h>

typedef int8_t crypto_int8;
typedef uint8_t crypto_uint8;
typedef int16_t crypto_int16;
typedef uint16_t crypto_uint16;
typedef int32_t crypto_int32;
typedef uint32_t crypto_uint32;

void	randombytes(unsigned char *, unsigned long long);
int	crypto_verify_32(const unsigned char *, const unsigned char *);

#define crypto_hashblocks_sha256_STATEBYTES 32U
#define crypto_hashblocks_sha256_BLOCKBYTES 64U
#define crypto_hash_sha256_BYTES 32U

int	crypto_hashblocks_sha256(unsigned char *, const unsigned char *,
    unsigned long long);
int	crypto_hash_sha256(unsigned char *, const unsigned char *,
    unsigned long long);

#define crypto_hashblocks_sha512_STATEBYTES 64U
#define crypto_hashblocks_sha512_BLOCKBYTES 128U
#define crypto_hash_sha512_BYTES 64U

int	crypto_hashblocks_sha512(unsigned char *, const unsigned char *,
    unsigned long long);
int	crypto_hash_sha512(unsigned char *, const unsigned char *,
    unsigned long long);

#define crypto_sign_ed25519_SECRETKEYBYTES 64U
#define crypto_sign_ed25519_PUBLICKEYBYTES 32U
#define crypto_sign_ed25519_BYTES 64U

int	crypto_sign_ed25519(unsigned char *, unsigned long long *,
    const unsigned char *, unsigned long long, const unsigned char *);
int	crypto_sign_ed25519_open(unsigned char *, unsigned long long *,
    const unsigned char *, unsigned long long, const unsigned char *);
int	crypto_sign_ed25519_keypair(unsigned char *, unsigned char *);

#endif /* crypto_api_h */
