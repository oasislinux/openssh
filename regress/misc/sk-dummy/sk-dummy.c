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

#include "includes.h"

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stddef.h>
#include <stdarg.h>

#include "crypto_api.h"
#include "sk-api.h"

#ifdef WITH_BEARSSL
#include <bearssl.h>
#endif /* WITH_BEARSSL */

/* #define SK_DEBUG 1 */

#if SSH_SK_VERSION_MAJOR != 0x000a0000
# error SK API has changed, sk-dummy.c needs an update
#endif

#ifdef SK_DUMMY_INTEGRATE
# define sk_api_version		ssh_sk_api_version
# define sk_enroll		ssh_sk_enroll
# define sk_sign		ssh_sk_sign
# define sk_load_resident_keys	ssh_sk_load_resident_keys
#endif /* !SK_STANDALONE */

static void skdebug(const char *func, const char *fmt, ...)
    __attribute__((__format__ (printf, 2, 3)));

static void
skdebug(const char *func, const char *fmt, ...)
{
#if defined(SK_DEBUG)
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "sk-dummy %s: ", func);
	vfprintf(stderr, fmt, ap);
	fputc('\n', stderr);
	va_end(ap);
#else
	(void)func; /* XXX */
	(void)fmt; /* XXX */
#endif
}

uint32_t
sk_api_version(void)
{
	return SSH_SK_VERSION_MAJOR;
}

static int
pack_key_ecdsa(struct sk_enroll_response *response)
{
#ifdef WITH_BEARSSL
	br_ec_private_key sk;
	br_ec_public_key pk;
	const br_prng_class *rng = &arc4random_prng;
	unsigned char skbuf[BR_EC_KBUF_PRIV_MAX_SIZE];
	unsigned char pkbuf[BR_EC_KBUF_PUB_MAX_SIZE];
	int ret = -1;

	response->public_key = NULL;
	response->public_key_len = 0;
	response->key_handle = NULL;
	response->key_handle_len = 0;

	if (br_ec_keygen(&rng, br_ec_get_default(), &sk, skbuf,
	    BR_EC_secp256r1) == 0) {
		skdebug(__func__, "br_ec_keygen");
		goto out;
	}
	if (br_ec_compute_pub(br_ec_get_default(), &pk, pkbuf, &sk) == 0) {
		skdebug(__func__, "br_ec_compute_pub");
		goto out;
	}
	response->public_key_len = pk.qlen;
	if (response->public_key_len == 0 || response->public_key_len > 2048) {
		skdebug(__func__, "bad pubkey length %zu",
		    response->public_key_len);
		goto out;
	}
	if ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	memcpy(response->public_key, pk.q, pk.qlen);
	/* Key handle contains serialized private key */
	response->key_handle_len = 1 + sk.xlen;
	if ((response->key_handle = malloc(response->key_handle_len)) == NULL) {
		skdebug(__func__, "malloc key_handle failed");
		goto out;
	}
	response->key_handle[0] = sk.curve;
	memcpy(response->key_handle + 1, sk.x, sk.xlen);
	/* success */
	ret = 0;
 out:
	if (ret != 0) {
		if (response->public_key != NULL) {
			memset(response->public_key, 0,
			    response->public_key_len);
			free(response->public_key);
			response->public_key = NULL;
		}
		if (response->key_handle != NULL) {
			memset(response->key_handle, 0,
			    response->key_handle_len);
			free(response->key_handle);
			response->key_handle = NULL;
		}
	}
	return ret;
#else
	return -1;
#endif
}

static int
pack_key_ed25519(struct sk_enroll_response *response)
{
	int ret = -1;
	u_char pk[crypto_sign_ed25519_PUBLICKEYBYTES];
	u_char sk[crypto_sign_ed25519_SECRETKEYBYTES];

	response->public_key = NULL;
	response->public_key_len = 0;
	response->key_handle = NULL;
	response->key_handle_len = 0;

	memset(pk, 0, sizeof(pk));
	memset(sk, 0, sizeof(sk));
	crypto_sign_ed25519_keypair(pk, sk);

	response->public_key_len = sizeof(pk);
	if ((response->public_key = malloc(response->public_key_len)) == NULL) {
		skdebug(__func__, "malloc pubkey failed");
		goto out;
	}
	memcpy(response->public_key, pk, sizeof(pk));
	/* Key handle contains sk */
	response->key_handle_len = sizeof(sk);
	if ((response->key_handle = malloc(response->key_handle_len)) == NULL) {
		skdebug(__func__, "malloc key_handle failed");
		goto out;
	}
	memcpy(response->key_handle, sk, sizeof(sk));
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
	response->flags = flags;
	switch(alg) {
	case SSH_SK_ECDSA:
		if (pack_key_ecdsa(response) != 0)
			goto out;
		break;
	case SSH_SK_ED25519:
		if (pack_key_ed25519(response) != 0)
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
sig_ecdsa(const uint8_t *message, size_t message_len,
    const char *application, uint32_t counter, uint8_t flags,
    const uint8_t *key_handle, size_t key_handle_len,
    struct sk_sign_response *response)
{
#ifdef WITH_BEARSSL
	int ret = -1;
	br_sha256_context ctx;
	br_ec_private_key sk;
	uint8_t sig[132];
	size_t siglen;
	uint8_t	apphash[br_sha256_SIZE];
	uint8_t	sighash[br_sha256_SIZE];
	uint8_t countbuf[4];

	/* Decode private key from key handle */
	if (key_handle_len == 0) {
		skdebug(__func__, "invalid key handle");
		goto out;
	}
	sk.curve = key_handle[0];
	sk.x = (unsigned char *)key_handle + 1;
	sk.xlen = key_handle_len - 1;
	/* Expect message to be pre-hashed */
	if (message_len != br_sha256_SIZE) {
		skdebug(__func__, "bad message len %zu", message_len);
		goto out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	br_sha256_init(&ctx);
	br_sha256_update(&ctx, application, strlen(application));
	br_sha256_out(&ctx, apphash);
	dump("apphash", apphash, sizeof(apphash));
	countbuf[0] = (counter >> 24) & 0xff;
	countbuf[1] = (counter >> 16) & 0xff;
	countbuf[2] = (counter >> 8) & 0xff;
	countbuf[3] = counter & 0xff;
	dump("countbuf", countbuf, sizeof(countbuf));
	dump("flags", &flags, sizeof(flags));
	br_sha256_init(&ctx);
	br_sha256_update(&ctx, apphash, sizeof(apphash));
	br_sha256_update(&ctx, &flags, sizeof(flags));
	br_sha256_update(&ctx, countbuf, sizeof(countbuf));
	br_sha256_update(&ctx, message, message_len);
	br_sha256_out(&ctx, sighash);
	dump("sighash", sighash, sizeof(sighash));
	/* create and encode signature */
	if ((siglen = br_ecdsa_sign_raw_get_default()(br_ec_get_default(),
	    &br_sha256_vtable, sighash, &sk, sig)) == 0 ||
	    siglen % 2 != 0) {
		skdebug(__func__, "br_ecdsa_sign_raw failed");
		goto out;
	}
	response->sig_r_len = siglen / 2;
	response->sig_s_len = siglen / 2;
	if ((response->sig_r = calloc(1, response->sig_r_len)) == NULL ||
	    (response->sig_s = calloc(1, response->sig_s_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	memcpy(response->sig_r, sig, siglen / 2);
	memcpy(response->sig_s, sig + siglen / 2, siglen / 2);
	ret = 0;
 out:
	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(&apphash, sizeof(apphash));
	explicit_bzero(&sighash, sizeof(sighash));
	explicit_bzero(sig, sizeof(sig));
	if (ret != 0) {
		free(response->sig_r);
		free(response->sig_s);
		response->sig_r = NULL;
		response->sig_s = NULL;
	}
	return ret;
#else
	return -1;
#endif
}

static int
sig_ed25519(const uint8_t *message, size_t message_len,
    const char *application, uint32_t counter, uint8_t flags,
    const uint8_t *key_handle, size_t key_handle_len,
    struct sk_sign_response *response)
{
	size_t o;
	int ret = -1;
	SHA2_CTX ctx;
	uint8_t	apphash[SHA256_DIGEST_LENGTH];
	uint8_t signbuf[sizeof(apphash) + sizeof(flags) +
	    sizeof(counter) + SHA256_DIGEST_LENGTH];
	uint8_t sig[crypto_sign_ed25519_BYTES + sizeof(signbuf)];
	unsigned long long smlen;

	if (key_handle_len != crypto_sign_ed25519_SECRETKEYBYTES) {
		skdebug(__func__, "bad key handle length %zu", key_handle_len);
		goto out;
	}
	/* Expect message to be pre-hashed */
	if (message_len != SHA256_DIGEST_LENGTH) {
		skdebug(__func__, "bad message len %zu", message_len);
		goto out;
	}
	/* Prepare data to be signed */
	dump("message", message, message_len);
	SHA256Init(&ctx);
	SHA256Update(&ctx, (const u_char *)application, strlen(application));
	SHA256Final(apphash, &ctx);
	dump("apphash", apphash, sizeof(apphash));

	memcpy(signbuf, apphash, sizeof(apphash));
	o = sizeof(apphash);
	signbuf[o++] = flags;
	signbuf[o++] = (counter >> 24) & 0xff;
	signbuf[o++] = (counter >> 16) & 0xff;
	signbuf[o++] = (counter >> 8) & 0xff;
	signbuf[o++] = counter & 0xff;
	memcpy(signbuf + o, message, message_len);
	o += message_len;
	if (o != sizeof(signbuf)) {
		skdebug(__func__, "bad sign buf len %zu, expected %zu",
		    o, sizeof(signbuf));
		goto out;
	}
	dump("signbuf", signbuf, sizeof(signbuf));
	/* create and encode signature */
	smlen = sizeof(signbuf);
	if (crypto_sign_ed25519(sig, &smlen, signbuf, sizeof(signbuf),
	    key_handle) != 0) {
		skdebug(__func__, "crypto_sign_ed25519 failed");
		goto out;
	}
	if (smlen <= sizeof(signbuf)) {
		skdebug(__func__, "bad sign smlen %llu, expected min %zu",
		    smlen, sizeof(signbuf) + 1);
		goto out;
	}
	response->sig_r_len = (size_t)(smlen - sizeof(signbuf));
	if ((response->sig_r = calloc(1, response->sig_r_len)) == NULL) {
		skdebug(__func__, "calloc signature failed");
		goto out;
	}
	memcpy(response->sig_r, sig, response->sig_r_len);
	dump("sig_r", response->sig_r, response->sig_r_len);
	ret = 0;
 out:
	explicit_bzero(&ctx, sizeof(ctx));
	explicit_bzero(&apphash, sizeof(apphash));
	explicit_bzero(&signbuf, sizeof(signbuf));
	explicit_bzero(&sig, sizeof(sig));
	if (ret != 0) {
		free(response->sig_r);
		response->sig_r = NULL;
	}
	return ret;
}

int
sk_sign(uint32_t alg, const uint8_t *data, size_t datalen,
    const char *application, const uint8_t *key_handle, size_t key_handle_len,
    uint8_t flags, const char *pin, struct sk_option **options,
    struct sk_sign_response **sign_response)
{
	struct sk_sign_response *response = NULL;
	int ret = SSH_SK_ERR_GENERAL;
	SHA2_CTX ctx;
	uint8_t message[32];

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
	SHA256Init(&ctx);
	SHA256Update(&ctx, data, datalen);
	SHA256Final(message, &ctx);
	response->flags = flags;
	response->counter = 0x12345678;
	switch(alg) {
	case SSH_SK_ECDSA:
		if (sig_ecdsa(message, sizeof(message), application,
		    response->counter, flags, key_handle, key_handle_len,
		    response) != 0)
			goto out;
		break;
	case SSH_SK_ED25519:
		if (sig_ed25519(message, sizeof(message), application,
		    response->counter, flags, key_handle, key_handle_len,
		    response) != 0)
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
	explicit_bzero(message, sizeof(message));
	if (response != NULL) {
		free(response->sig_r);
		free(response->sig_s);
		free(response);
	}
	return ret;
}

int
sk_load_resident_keys(const char *pin, struct sk_option **options,
    struct sk_resident_key ***rks, size_t *nrks)
{
	return SSH_SK_ERR_UNSUPPORTED;
}
