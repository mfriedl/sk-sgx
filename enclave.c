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
#include "sgx_tseal.h"
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

/* key handle contains AES-GCM-sealed sk, application is used as AAD */
int
ecall_sk_get_key_handle_len_ed25519(const char *application,
    size_t *key_handle_len)
{
	int ret = -1;
	size_t alen;

	if (key_handle_len == NULL || application == NULL) {
		debug("%s: NULL", __func__);
		goto out;
	}
	alen = strlen(application);
	if (alen >= UINT32_MAX) {
		debug("%s: application too long: %zu", __func__, alen);
		goto out;
	}
	*key_handle_len = sgx_calc_sealed_data_size((uint32_t)alen,
	    crypto_sign_ed25519_SECRETKEYBYTES);
	/* success */
	ret = 0;
 out:
	return ret;
}

int
ecall_sk_enroll_ed25519(const char *application,
    uint8_t *public_key, size_t public_key_len,
    uint8_t *key_handle, size_t key_handle_len)
{
	int ret = -1;
	int r;
	uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint32_t aadlen, key_handle_need;
	size_t alen;

	if (public_key == NULL || key_handle == NULL || application == NULL) {
		debug("%s: NULL", __func__);
		goto out;
	}
	if (public_key_len != crypto_sign_ed25519_PUBLICKEYBYTES) {
		debug("%s: public_key_len", __func__);
		goto out;
	}
	/* Seal private key */
	alen = strlen(application);
	if (alen >= UINT32_MAX) {
		debug("%s: application too long: %zu", __func__, alen);
		goto out;
	}
	aadlen = (uint32_t)alen;
	key_handle_need = sgx_calc_sealed_data_size(aadlen, sizeof(sk));
	if (key_handle_len != key_handle_need) {
		debug("%s: key_handle_len %zu != need %u", __func__,
		    key_handle_len, key_handle_need);
		goto out;
	}
	crypto_sign_ed25519_keypair(public_key, sk);
	if ((r = sgx_seal_data(aadlen, (const uint8_t*)application,
	    sizeof(sk), sk, key_handle_need, (sgx_sealed_data_t *)key_handle))
	    != SGX_SUCCESS) {
		debug("%s: sgx_seal_data failed with %d", __func__, r);
		goto out;
	}

	/* success */
	ret = 0;
 out:
	explicit_bzero(&sk, sizeof(sk));
	return ret;
}

int
ecall_sk_sign_ed25519(const uint8_t *message, size_t message_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, uint32_t *counter, uint8_t *sig_r, size_t sig_r_len)
{
	size_t o;
	int ret = -1;
	int r;
	uint8_t	apphash[crypto_hash_sha256_BYTES];
	uint8_t signbuf[sizeof(apphash) + sizeof(flags) +
	    sizeof(*counter) + crypto_hash_sha256_BYTES];
	uint8_t sig[crypto_sign_ed25519_BYTES + sizeof(signbuf)];
	uint8_t sk[crypto_sign_ed25519_SECRETKEYBYTES];
	uint8_t *unsealed_application = NULL;
	uint32_t aadlen, sklen, key_handle_need;
	size_t alen;
	const sgx_sealed_data_t *sealed = (const sgx_sealed_data_t *)key_handle;
	unsigned long long smlen;

	if (message == NULL || application == NULL || key_handle == NULL ||
	    sig_r == NULL) {
		debug("%s: NULL", __func__);
		goto out;
	}
	/* Expect message to be pre-hashed */
	if (message_len != crypto_hash_sha256_BYTES) {
		debug("%s: bad message len %zu", __func__, message_len);
		goto out;
	}

	/* Extract sealed private key */
	sklen = sgx_get_encrypt_txt_len(sealed);
	if (sklen != sizeof(sk)) {
		debug("%s: sklen %u != sizeof(sk) %zu", __func__,
		    sklen, sizeof(sk));
		goto out;
	}
	alen = strlen(application);
	if (alen >= UINT32_MAX) {
		debug("%s: application too long: %zu", __func__, alen);
		goto out;
	}
	aadlen = sgx_get_add_mac_txt_len(sealed);
	if (aadlen != alen) {
		debug("%s: aadlen %u != alen %zu", __func__, aadlen, alen);
		goto out;
	}
	key_handle_need = sgx_calc_sealed_data_size(aadlen, sklen);
	if (key_handle_len < key_handle_need) {
		debug("%s: key_handle_len %zu < need %u", __func__,
		    key_handle_len, key_handle_need);
		goto out;
	}
	if ((unsealed_application = malloc(aadlen)) == NULL) {
		debug("%s: malloc addlen %u", __func__, aadlen);
		goto out;
	}
	if ((r = sgx_unseal_data(sealed, unsealed_application, &aadlen,
	    sk, &sklen)) != SGX_SUCCESS) {
		debug("%s: sgx_unseal_data failed with %d", __func__, r);
		goto out;
	}
	if (aadlen != alen) {
		debug("%s: unsealed aadlen %u != alen %zu",
		    __func__, aadlen, alen);
		goto out;
	}
	if (consttime_memequal(unsealed_application, application, alen) == 0) {
		debug("%s: unsealed_application %s does not match %s", __func__,
		    (char *)unsealed_application, application);
		goto out;
	}

	/* Prepare data to be signed */
	dump("message", message, message_len);
	crypto_hash_sha256(apphash, unsealed_application, aadlen);
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
	if (crypto_sign_ed25519(sig, &smlen, signbuf, sizeof(signbuf), sk)
	    != 0) {
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
	explicit_bzero(&sk, sizeof(sk));
	if (unsealed_application) {
		explicit_bzero(unsealed_application, aadlen);
		free(unsealed_application);
	}
	return ret;
}
