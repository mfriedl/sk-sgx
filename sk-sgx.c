/*
 * Copyright (c) 2019 Markus Friedl
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
#include "sk-api.h"

#include "sgx_urts.h"
#include "sk_u.h"

/* #define SK_DEBUG 1 */

#if SSH_SK_VERSION_MAJOR != 0x00040000
# error SK API has changed, sk-dummy.c needs an update
#endif

#define ENCLAVE_FILENAME "enclave.signed.so"
sgx_enclave_id_t global_eid = 0;

static void skdebug(const char *func, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

static void
skdebug(const char *func, const char *fmt, ...)
{
#if defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-sgx %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#else
	(void)func; /* XXX */
	(void)fmt; /* XXX */
#endif
}

void
ocall_puts(const char *str)
{
#if defined(SK_DEBUG)
	fprintf(stderr, "%s", str);
	fflush(stderr);
#endif
}

static int
initialize_enclave(void)
{
	sgx_status_t ret;

	ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL,
	    &global_eid, NULL);
	if (ret != SGX_SUCCESS) {
		skdebug(__func__, "sgx_create_enclave returns %d", ret);
		return -1;
	}
	return 0;
}

uint32_t
sk_api_version(void)
{
	return SSH_SK_VERSION_MAJOR;
}

static int
pack_key_ed25519(const char *application,  struct sk_enroll_response *response)
{
	int ret = -1;
	int r;

	response->public_key = NULL;
	response->key_handle = NULL;

	response->public_key_len = crypto_sign_ed25519_PUBLICKEYBYTES;
	if ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	/* Key handle contains sk */
	/* XXX will be encrypted in the future */
	response->key_handle_len = crypto_sign_ed25519_SECRETKEYBYTES;
	if ((response->key_handle = malloc(response->key_handle_len)) == NULL) {
		skdebug(__func__, "malloc key_handle failed");
		goto out;
	}
	if (ecall_sk_enroll_ed25519(global_eid, &r, application,
	    response->public_key, response->public_key_len,
	    response->key_handle, response->key_handle_len) != SGX_SUCCESS) {
		skdebug(__func__, "calling ecall_sk_enroll_ed25519 failed");
		goto out;
	}
	if (r != 0) {
		skdebug(__func__, "ecall_sk_enroll_ed25519 failed: %d", r);
		goto out;
	}
	/* success */
	ret = 0;
 out:
	if (ret != 0)
		free(response->public_key);
	return ret;
}

static int
check_options(struct sk_option **options)
{
	size_t i;

	if (options == NULL)
		return 0;
	for (i = 0; options[i] != NULL; i++) {
		skdebug(__func__, "requested unsupported option %s",
		    options[i]->name);
		if (options[i]->required) {
			skdebug(__func__, "unknown required option");
			return -1;
		}
	}
	return 0;
}

int
sk_enroll(uint32_t alg, const uint8_t *challenge, size_t challenge_len,
    const char *application, uint8_t flags, const char *pin,
    struct sk_option **options, struct sk_enroll_response **enroll_response)
{
	struct sk_enroll_response *response = NULL;
	int ret = SSH_SK_ERR_GENERAL;

	(void)flags; /* XXX; unused */

	if (initialize_enclave() != 0)
		goto out;
	if (enroll_response == NULL) {
		skdebug(__func__, "enroll_response == NULL");
		goto out;
	}
	*enroll_response = NULL;
	if (check_options(options) != 0)
		goto out; /* error already logged */
	if ((response = calloc(1, sizeof(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	switch(alg) {
	case SSH_SK_ED25519:
		if (pack_key_ed25519(application, response) != 0)
			goto out;
		break;
	default:
		skdebug(__func__, "unsupported key type %d", alg);
		return -1;
	}
	/* Have to return something here */
	if ((response->signature = calloc(1, 1)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	response->signature_len = 0;

	*enroll_response = response;
	response = NULL;
	ret = 0;
 out:
	if (response != NULL) {
		free(response->public_key);
		free(response->key_handle);
		free(response->signature);
		free(response->attestation_cert);
		free(response);
	}
	if (global_eid != 0)
		sgx_destroy_enclave(global_eid);
	return ret;
}

static void
dump(const char *preamble, const void *sv, size_t l)
{
#ifdef SK_DEBUG
	const u_char *s = (const u_char *)sv;
	size_t i;

	fprintf(stderr, "%s (len %zu):\n", preamble, l);
	for (i = 0; i < l; i++) {
		if (i % 16 == 0)
			fprintf(stderr, "%04zu: ", i);
		fprintf(stderr, "%02x", s[i]);
		if (i % 16 == 15 || i == l - 1)
			fprintf(stderr, "\n");
	}
#endif
}

static int
sig_ed25519(const uint8_t *message, size_t message_len,
    const char *application, uint8_t flags,
    const uint8_t *key_handle, size_t key_handle_len,
    struct sk_sign_response *response)
{
	int ret = -1;
	int r;

	response->sig_r_len = crypto_sign_ed25519_BYTES;
	if ((response->sig_r = calloc(1, response->sig_r_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	if (ecall_sk_sign_ed25519(global_eid, &r,
	    message, message_len, application, key_handle, key_handle_len,
	    flags, &response->counter,
	    response->sig_r, response->sig_r_len) != SGX_SUCCESS) {
		skdebug(__func__, "calling ecall_sk_sign_ed25519 failed");
		goto out;
	}
	if (r != 0) {
		skdebug(__func__, "ecall_sk_sign_ed25519 failed: %d", r);
		goto out;
	}
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	if (ret != 0) {
		free(response->sig_r);
		response->sig_r = NULL;
	}
	return ret;
}

int
sk_sign(uint32_t alg, const uint8_t *message, size_t message_len,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const char *pin, struct sk_option **options,
    struct sk_sign_response **sign_response)
{
	struct sk_sign_response *response = NULL;
	int ret = SSH_SK_ERR_GENERAL;

	if (initialize_enclave() != 0)
		goto out;
	if (sign_response == NULL) {
		skdebug(__func__, "sign_response == NULL");
		goto out;
	}
	*sign_response = NULL;
	if (check_options(options) != 0)
		goto out; /* error already logged */
	if ((response = calloc(1, sizeof(*response))) == NULL) {
		skdebug(__func__, "calloc response failed");
		goto out;
	}
	response->flags = flags;
	response->counter = 0;
	switch(alg) {
	case SSH_SK_ED25519:
		if (sig_ed25519(message, message_len, application,
		    flags, key_handle, key_handle_len, response) != 0)
			goto out;
		break;
	default:
		skdebug(__func__, "unsupported key type %d", alg);
		return -1;
	}
	*sign_response = response;
	response = NULL;
	ret = 0;
 out:
	if (response != NULL) {
		free(response->sig_r);
		free(response->sig_s);
		free(response);
	}
	if (global_eid != 0)
		sgx_destroy_enclave(global_eid);
	return ret;
}

int
sk_load_resident_keys(const char *pin, struct sk_option **options,
    struct sk_resident_key ***rks, size_t *nrks)
{
	return SSH_SK_ERR_UNSUPPORTED;
}

#ifdef TEST
int
main(int argc, char **argv)
{
	struct sk_enroll_response *enroll = NULL;
	struct sk_sign_response *sign = NULL;
	char *app = "markus";
	unsigned char chall[32];
	unsigned char msg[32];

	memset(chall, 'c', sizeof(chall));
	if (sk_enroll(SSH_SK_ED25519, chall, sizeof(chall), app, 0, NULL, NULL,
	    &enroll) != 0) {
		printf("enroll failed\n");
		return 1;
	}
	memset(msg, 'm', sizeof(msg));
	if (sk_sign(SSH_SK_ED25519, msg, sizeof(msg), app, enroll->key_handle,
	    enroll->key_handle_len, 0, NULL, NULL, &sign) != 0) {
		printf("sign failed\n");
		return 2;
	}
	printf("ok\n");
	return 0;
}
#endif
