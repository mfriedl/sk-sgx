/*
 * Copyright (c) 2020 Markus Friedl
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>

#include "crypto_api.h"

#include "sgx_trts.h"
#include "sk_t.h"

#define explicit_bzero(s, n) memset_s(s, n, 0, n)

#if defined(SK_DEBUG)
static void debug(const char *fmt, ...)
    __attribute__((__format__ (printf, 1, 2)));

static void
debug(const char *fmt, ...)
{
	char buf[BUFSIZ];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, BUFSIZ, fmt, ap);
	va_end(ap);
	ocall_puts(buf);
}

static void
dump(const char *preamble, const void *sv, size_t l)
{
	const uint8_t *s = (const uint8_t *)sv;
	size_t i;

	debug("%s (len %zu):\n", preamble, l);
	for (i = 0; i < l; i++) {
		if (i % 16 == 0)
			debug("%04zu: ", i);
		debug("%02x", s[i]);
		if (i % 16 == 15 || i == l - 1)
			debug("\n");
	}
}
#else
#define debug(fmt, ...)
#define dump(p,v,l)
#endif

void
randombytes(unsigned char *buf, unsigned long long nbytes)
{
	if (sgx_read_rand(buf, nbytes) != SGX_SUCCESS)
		abort();
}

int
ecall_sk_enroll_ed25519(const char *application,
    uint8_t *public_key, size_t public_key_len,
    uint8_t *key_handle, size_t key_handle_len)
{
	int ret = -1;

	if (public_key == NULL || key_handle == NULL) {
		debug("%s: NULL", __func__);
		goto out;
	}
	if (public_key_len != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug("%s: public_key_len", __func__);
		goto out;
	}
	if (key_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		debug("%s: key_handle_len", __func__);
		goto out;
	}
	crypto_sign_ed25519_keypair(public_key, key_handle);
	/* success */
	ret = 0;
 out:
	return ret;
}

int
ecall_sk_sign_ed25519(const uint8_t *message, size_t message_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, uint32_t *counter, uint8_t *sig_r, size_t sig_r_len)
{
	size_t o;
	int ret = -1;
	uint8_t	apphash[crypto_hash_sha256_BYTES];
	uint8_t signbuf[sizeof(apphash) + sizeof(flags) +
	    sizeof(*counter) + crypto_hash_sha256_BYTES];
	uint8_t sig[crypto_sign_ed25519_BYTES + sizeof(signbuf)];
	unsigned long long smlen;

	if (message == NULL || application == NULL || key_handle == NULL ||
	    sig_r == NULL) {
		debug("%s: NULL", __func__);
		goto out;
	}
	if (key_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		debug("%s: bad key handle length %zu", __func__, key_handle_len);
		goto out;
	}
	/* Expect message to be pre-hashed */
	if (message_len != crypto_hash_sha256_BYTES) {
		debug("%s: bad message len %zu", __func__, message_len);
		goto out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	crypto_hash_sha256(apphash, application, strlen(application));
	dump("apphash", apphash, sizeof(apphash));

	memcpy(signbuf, apphash, sizeof(apphash));
	o = sizeof(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (uint8_t)((*counter >> 24) & 0xff);
	signbuf[o++] = (uint8_t)((*counter >> 16) & 0xff);
	signbuf[o++] = (uint8_t)((*counter >> 8) & 0xff);
	signbuf[o++] = (uint8_t)(*counter & 0xff);
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	if (o != sizeof(signbuf)) {
		debug("%s: bad sign buf len %zu, expected %zu",
		    __func__, o, sizeof(signbuf));
		goto out;
	}
	dump("signbuf", signbuf, sizeof(signbuf));
	/* create and encode signature */
	smlen = sizeof(signbuf);
	if (crypto_sign_ed25519(sig, &smlen, signbuf, sizeof(signbuf),
	    key_handle) != 0) {
		debug("%s: crypto_sign_ed25519 failed", __func__);
		goto out;
	}
	if (smlen <= sizeof(signbuf)) {
		debug("%s: bad sign smlen %llu, expected min %zu", __func__,
		    smlen, sizeof(signbuf) + 1);
		goto out;
	}
	if (sig_r_len != (size_t)(smlen - sizeof(signbuf))) {
		debug("%s: sig_len wrong", __func__);
		goto out;
	}
	memcpy(sig_r, sig, sig_r_len);
	dump("sig_r", sig_r, sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&apphash, sizeof(apphash));
	explicit_bzero(&signbuf, sizeof(signbuf));
	explicit_bzero(&sig, sizeof(sig));
	return ret;
}
