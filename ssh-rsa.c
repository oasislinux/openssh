/* $OpenBSD: ssh-rsa.c,v 1.79 2023/03/05 05:34:09 dtucker Exp $ */
/*
 * Copyright (c) 2000, 2003 Markus Friedl <markus@openbsd.org>
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

#ifdef WITH_BEARSSL

#include <sys/types.h>

#include <bearssl.h>

#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"
#include "log.h"

/* The modulus is assumed to have no leading zeros. This is handled
 * by sshbuf_get_bignum2_bytes_direct(). */
static int
rsa_bitlen(const u_char *n, size_t nlen)
{
	int bitlen;
	u_char x;

	bitlen = (nlen - 1) * 8;
	for (x = n[0]; x > 0; x >>= 1)
		++bitlen;

	return bitlen;
}

static u_int
ssh_rsa_size(const struct sshkey *key)
{
	if (key->rsa_pk == NULL)
		return 0;
	return rsa_bitlen(key->rsa_pk->key.n, key->rsa_pk->key.nlen);
}

static void
ssh_rsa_cleanup(struct sshkey *k)
{
	freezero(k->rsa_pk, sizeof(*k->rsa_pk));
	k->rsa_pk = NULL;
	freezero(k->rsa_sk, sizeof(*k->rsa_sk));
	k->rsa_sk = NULL;
}

static int
ssh_rsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a->rsa_pk == NULL || b->rsa_pk == NULL)
		return 0;
	if (a->rsa_pk->key.nlen != b->rsa_pk->key.nlen)
		return 0;
	if (memcmp(a->rsa_pk->key.n, b->rsa_pk->key.n, a->rsa_pk->key.nlen) != 0)
		return 0;
	if (a->rsa_pk->key.elen != b->rsa_pk->key.elen)
		return 0;
	if (memcmp(a->rsa_pk->key.e, b->rsa_pk->key.e, a->rsa_pk->key.elen) != 0)
		return 0;
	return 1;
}

static int
ssh_rsa_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if (key->rsa_pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshbuf_put_bignum2_bytes(b, key->rsa_pk->key.e,
	    key->rsa_pk->key.elen)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(b, key->rsa_pk->key.n,
	    key->rsa_pk->key.nlen)) != 0)
		return r;

	return 0;
}

static int
ssh_rsa_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if (!sshkey_is_cert(key)) {
		/* Note: can't reuse ssh_rsa_serialize_public: e, n vs. n, e */
		if ((r = sshbuf_put_bignum2_bytes(b, key->rsa_pk->key.n,
		    key->rsa_pk->key.nlen)) != 0 ||
		    (r = sshbuf_put_bignum2_bytes(b, key->rsa_pk->key.e,
		    key->rsa_pk->key.elen)) != 0)
			return r;
	}
	if ((r = sshbuf_put_bignum2_bytes(b, key->rsa_sk->d,
	    key->rsa_sk->dlen)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(b, key->rsa_sk->key.iq,
	    key->rsa_sk->key.iqlen)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(b, key->rsa_sk->key.p,
	    key->rsa_sk->key.plen)) != 0 ||
	    (r = sshbuf_put_bignum2_bytes(b, key->rsa_sk->key.q,
	    key->rsa_sk->key.qlen)) != 0)
		return r;

	return 0;
}

static int
ssh_rsa_generate(struct sshkey *k, int bits)
{
	struct sshkey_rsa_pk *rsa_pk;
	struct sshkey_rsa_sk *rsa_sk;
	const br_prng_class *rng = &arc4random_prng;
	br_rsa_compute_privexp privexp;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (bits < SSH_RSA_MINIMUM_MODULUS_SIZE ||
	    bits > SSH_RSA_MAXIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;
	if ((rsa_pk = calloc(1, sizeof(*rsa_pk))) == NULL ||
	    (rsa_sk = calloc(1, sizeof(*rsa_sk))) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	privexp = br_rsa_compute_privexp_get_default();
	if (br_rsa_keygen_get_default()(&rng, &rsa_sk->key,
	    rsa_sk->data, &rsa_pk->key, rsa_pk->data,
	    bits, 3) != 1 ||
	    privexp(NULL, &rsa_sk->key, 3) >= sizeof(rsa_sk->d) ||
	    (rsa_sk->dlen = privexp(rsa_sk->d,
	    &rsa_sk->key, 3)) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	k->rsa_pk = rsa_pk;
	rsa_pk = NULL;
	k->rsa_sk = rsa_sk;
	rsa_sk = NULL;
	ret = 0;
out:
	freezero(rsa_pk, sizeof(*rsa_pk));
	freezero(rsa_sk, sizeof(*rsa_sk));
	return ret;
}

static int
ssh_rsa_copy_public(const struct sshkey *from, struct sshkey *to)
{
	if ((to->rsa_pk = calloc(1, sizeof(*to->rsa_pk))) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	to->rsa_pk->key.n = to->rsa_pk->data;
	to->rsa_pk->key.nlen = from->rsa_pk->key.nlen;
	memcpy(to->rsa_pk->key.n, from->rsa_pk->key.n, from->rsa_pk->key.nlen);
	to->rsa_pk->key.e = to->rsa_pk->data + to->rsa_pk->key.nlen;
	to->rsa_pk->key.elen = from->rsa_pk->key.elen;
	memcpy(to->rsa_pk->key.e, from->rsa_pk->key.e, from->rsa_pk->key.elen);
	return 0;
}

static int
ssh_rsa_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshkey_rsa_pk *rsa_pk;
	const u_char *rsa_n, *rsa_e;
	size_t rsa_nlen, rsa_elen;

	if ((rsa_pk = calloc(1, sizeof(*rsa_pk))) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_bignum2_bytes_direct(b, &rsa_e, &rsa_elen) != 0 ||
	    sshbuf_get_bignum2_bytes_direct(b, &rsa_n, &rsa_nlen) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (rsa_elen + rsa_nlen > sizeof(rsa_pk->data)) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	rsa_pk->key.e = rsa_pk->data;
	rsa_pk->key.elen = rsa_elen;
	memcpy(rsa_pk->key.e, rsa_e, rsa_elen);

	rsa_pk->key.n = rsa_pk->key.e + rsa_elen;
	rsa_pk->key.nlen = rsa_nlen;
	memcpy(rsa_pk->key.n, rsa_n, rsa_nlen);

	key->rsa_pk = rsa_pk;
	rsa_pk = NULL;

	if ((ret = sshkey_check_rsa_length(key, 0)) != 0)
		goto out;
#ifdef DEBUG_PK
	/* XXX */
#endif
	/* success */
	ret = 0;
 out:
	freezero(rsa_pk, sizeof(*rsa_pk));
	return ret;
}

static int
ssh_rsa_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;
	const u_char *rsa_n, *rsa_e, *rsa_d, *rsa_iq, *rsa_p, *rsa_q;
	size_t rsa_nlen, rsa_elen, rsa_dlen, rsa_iqlen, rsa_plen, rsa_qlen;

	/* Note: can't reuse ssh_rsa_deserialize_public: e, n vs. n, e */
	if (!sshkey_is_cert(key)) {
		if ((key->rsa_pk = calloc(1, sizeof(*key->rsa_pk))) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}

		if ((r = sshbuf_get_bignum2_bytes_direct(b, &rsa_n,
		    &rsa_nlen)) != 0 ||
		    (r = sshbuf_get_bignum2_bytes_direct(b, &rsa_e,
		    &rsa_elen)) != 0)
			goto out;
		if (rsa_nlen + rsa_elen > sizeof(key->rsa_pk->data)) {
			r = SSH_ERR_LIBCRYPTO_ERROR;
			goto out;
		}
		key->rsa_pk->key.n = key->rsa_pk->data;
		key->rsa_pk->key.nlen = rsa_nlen;
		memcpy(key->rsa_pk->key.n, rsa_n, rsa_nlen);

		key->rsa_pk->key.e = key->rsa_pk->data + rsa_nlen;
		key->rsa_pk->key.elen = rsa_elen;
		memcpy(key->rsa_pk->key.e, rsa_e, rsa_elen);
	}

	if ((key->rsa_sk = calloc(1, sizeof(*key->rsa_sk))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	key->rsa_sk->key.n_bitlen = rsa_bitlen(key->rsa_pk->key.n,
	    key->rsa_pk->key.nlen);
	if (key->rsa_sk->key.n_bitlen < SSH_RSA_MINIMUM_MODULUS_SIZE) {
		r = SSH_ERR_KEY_LENGTH;
		goto out;
	}

	if ((r = sshbuf_get_bignum2_bytes_direct(b, &rsa_d, &rsa_dlen)) != 0 ||
	    (r = sshbuf_get_bignum2_bytes_direct(b, &rsa_iq, &rsa_iqlen)) != 0 ||
	    (r = sshbuf_get_bignum2_bytes_direct(b, &rsa_p, &rsa_plen)) != 0 ||
	    (r = sshbuf_get_bignum2_bytes_direct(b, &rsa_q, &rsa_qlen)) != 0)
		goto out;
	if (rsa_dlen > sizeof(key->rsa_sk->d) ||
	    rsa_iqlen + 2 * rsa_plen + 2 * rsa_qlen >
	    sizeof(key->rsa_sk->data)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	key->rsa_sk->dlen = rsa_dlen;
	memcpy(key->rsa_sk->d, rsa_d, rsa_dlen);

	key->rsa_sk->key.iq = key->rsa_sk->data;
	key->rsa_sk->key.iqlen = rsa_iqlen;
	memcpy(key->rsa_sk->key.iq, rsa_iq, rsa_iqlen);

	key->rsa_sk->key.p = key->rsa_sk->key.iq + key->rsa_sk->key.iqlen;
	key->rsa_sk->key.plen = rsa_plen;
	memcpy(key->rsa_sk->key.p, rsa_p, rsa_plen);

	key->rsa_sk->key.q = key->rsa_sk->key.p + key->rsa_sk->key.plen;
	key->rsa_sk->key.qlen = rsa_qlen;
	memcpy(key->rsa_sk->key.q, rsa_q, rsa_qlen);

	if ((r = ssh_rsa_complete_crt_parameters(key->rsa_sk, key->rsa_sk->key.q +
	    key->rsa_sk->key.qlen, sizeof(key->rsa_sk->data) -
	    (rsa_iqlen + rsa_plen + rsa_qlen))) != 0)
		goto out;
	/* success */
	r = 0;
 out:
	if (r != 0) {
		freezero(key->rsa_pk, sizeof(*key->rsa_pk));
		key->rsa_pk = NULL;
		freezero(key->rsa_sk, sizeof(*key->rsa_sk));
		key->rsa_sk = NULL;
	}
	return r;
}

static const char *
rsa_hash_alg_ident(int hash_alg)
{
	switch (hash_alg) {
	case SSH_DIGEST_SHA1:
		return "ssh-rsa";
	case SSH_DIGEST_SHA256:
		return "rsa-sha2-256";
	case SSH_DIGEST_SHA512:
		return "rsa-sha2-512";
	}
	return NULL;
}

/*
 * Returns the hash algorithm ID for a given algorithm identifier as used
 * inside the signature blob,
 */
static int
rsa_hash_id_from_ident(const char *ident)
{
	if (strcmp(ident, "ssh-rsa") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(ident, "rsa-sha2-256") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(ident, "rsa-sha2-512") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

/*
 * Return the hash algorithm ID for the specified key name. This includes
 * all the cases of rsa_hash_id_from_ident() but also the certificate key
 * types.
 */
static int
rsa_hash_id_from_keyname(const char *alg)
{
	int r;

	if ((r = rsa_hash_id_from_ident(alg)) != -1)
		return r;
	if (strcmp(alg, "ssh-rsa-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA1;
	if (strcmp(alg, "rsa-sha2-256-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA256;
	if (strcmp(alg, "rsa-sha2-512-cert-v01@openssh.com") == 0)
		return SSH_DIGEST_SHA512;
	return -1;
}

static const u_char *
rsa_hash_alg_oid(int type)
{
	switch (type) {
	case SSH_DIGEST_SHA1:
		return BR_HASH_OID_SHA1;
	case SSH_DIGEST_SHA256:
		return BR_HASH_OID_SHA256;
	case SSH_DIGEST_SHA512:
		return BR_HASH_OID_SHA512;
	default:
		return NULL;
	}
}

int
ssh_rsa_complete_crt_parameters(struct sshkey_rsa_sk *rsa, u_char *buf, size_t len)
{
	void br_i31_decode(uint32_t *, const void *, size_t);
	void br_i31_reduce(uint32_t *, const uint32_t *, const uint32_t *);
	void br_i31_encode(void *, size_t, const uint32_t *);
	uint32_t d[1 + (SSH_RSA_MAXIMUM_MODULUS_SIZE + 30) / 31];
	uint32_t dm1[1 + (SSH_RSA_MAXIMUM_MODULUS_SIZE + 30) / 31];
	uint32_t aux[1 + (SSH_RSA_MAXIMUM_MODULUS_SIZE + 30) / 31];

	if (rsa == NULL ||
	    rsa->dlen > (SSH_RSA_MAXIMUM_MODULUS_SIZE + 7) / 8 ||
	    rsa->key.plen > (SSH_RSA_MAXIMUM_MODULUS_SIZE + 7) / 8 ||
	    rsa->key.qlen > (SSH_RSA_MAXIMUM_MODULUS_SIZE + 7) / 8 ||
	    rsa->key.plen + rsa->key.qlen > len ||
	    rsa->key.p[rsa->key.plen - 1] % 2 != 1 ||
	    rsa->key.q[rsa->key.qlen - 1] % 2 != 1)
		return SSH_ERR_INVALID_ARGUMENT;

	br_i31_decode(d, rsa->d, rsa->dlen);

	/* Compute d mod (p - 1) */
	br_i31_decode(aux, rsa->key.p, rsa->key.plen);
	--aux[1];
	br_i31_reduce(dm1, d, aux);
	rsa->key.dp = buf;
	rsa->key.dplen = rsa->key.plen;
	br_i31_encode(rsa->key.dp, rsa->key.dplen, dm1);

	/* Compute d mod (q - 1) */
	br_i31_decode(aux, rsa->key.q, rsa->key.qlen);
	--aux[1];
	br_i31_reduce(dm1, d, aux);
	rsa->key.dq = buf + rsa->key.dplen;
	rsa->key.dqlen = rsa->key.qlen;
	br_i31_encode(rsa->key.dq, rsa->key.dqlen, dm1);

	explicit_bzero(d, sizeof(d));
	explicit_bzero(dm1, sizeof(dm1));
	explicit_bzero(aux, sizeof(aux));

	return 0;
}

/* RSASSA-PKCS1-v1_5 (PKCS #1 v2.0 signature) with SHA1 */
static int
ssh_rsa_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	u_char digest[SSH_DIGEST_MAX_LENGTH], *sig = NULL;
	size_t slen = 0;
	u_int hlen, len;
	int hash_alg, ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	const u_char *oid;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (alg == NULL || strlen(alg) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	else
		hash_alg = rsa_hash_id_from_keyname(alg);
	if (key == NULL || key->rsa_sk == NULL || hash_alg == -1 ||
	    (oid = rsa_hash_alg_oid(hash_alg)) == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA)
		return SSH_ERR_INVALID_ARGUMENT;
	if (key->rsa_sk->key.n_bitlen < SSH_RSA_MINIMUM_MODULUS_SIZE)
		return SSH_ERR_KEY_LENGTH;
	slen = (key->rsa_sk->key.n_bitlen + 7) / 8;
	if (slen <= 0 || slen > SSHBUF_MAX_BIGNUM)
		return SSH_ERR_INVALID_ARGUMENT;

	/* hash the data */
	if ((hlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if ((sig = malloc(slen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (br_rsa_pkcs1_sign_get_default()(oid, digest, hlen,
	    &key->rsa_sk->key, sig) != 1) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* encode signature */
	if ((b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_cstring(b, rsa_hash_alg_ident(hash_alg))) != 0 ||
	    (ret = sshbuf_put_string(b, sig, slen)) != 0)
		goto out;
	len = sshbuf_len(b);
	if (sigp != NULL) {
		if ((*sigp = malloc(len)) == NULL) {
			ret = SSH_ERR_ALLOC_FAIL;
			goto out;
		}
		memcpy(*sigp, sshbuf_ptr(b), len);
	}
	if (lenp != NULL)
		*lenp = len;
	ret = 0;
 out:
	explicit_bzero(digest, sizeof(digest));
	freezero(sig, slen);
	sshbuf_free(b);
	return ret;
}

static int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	char *sigtype = NULL;
	int hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, hlen;
	struct sshbuf *b = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH], sigdigest[SSH_DIGEST_MAX_LENGTH];
	const u_char *sigblob, *oid;

	if (key == NULL || key->rsa_pk == NULL ||
	    sshkey_type_plain(key->type) != KEY_RSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &sigtype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if ((hash_alg = rsa_hash_id_from_ident(sigtype)) == -1 ||
	    (oid = rsa_hash_alg_oid(hash_alg)) == NULL) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	/*
	 * Allow ssh-rsa-cert-v01 certs to generate SHA2 signatures for
	 * legacy reasons, but otherwise the signature type should match.
	 */
	if (alg != NULL && strcmp(alg, "ssh-rsa-cert-v01@openssh.com") != 0) {
		if ((want_alg = rsa_hash_id_from_keyname(alg)) == -1) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		if (hash_alg != want_alg) {
			ret = SSH_ERR_SIGNATURE_INVALID;
			goto out;
		}
	}
	if (sshbuf_get_string_direct(b, &sigblob, &len) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if ((hlen = ssh_digest_bytes(hash_alg)) == 0) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((ret = ssh_digest_memory(hash_alg, data, dlen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if (br_rsa_pkcs1_vrfy_get_default()(sigblob, len, oid, hlen,
	    &key->rsa_pk->key, sigdigest) != 1 ||
	    timingsafe_bcmp(digest, sigdigest, dlen) != 0) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	ret = 0;
 out:
	free(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, sizeof(digest));
	explicit_bzero(sigdigest, sizeof(sigdigest));
	return ret;
}

static const struct sshkey_impl_funcs sshkey_rsa_funcs = {
	/* .size = */		ssh_rsa_size,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_rsa_cleanup,
	/* .equal = */		ssh_rsa_equal,
	/* .ssh_serialize_public = */ ssh_rsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_rsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_rsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_rsa_deserialize_private,
	/* .generate = */	ssh_rsa_generate,
	/* .copy_public = */	ssh_rsa_copy_public,
	/* .sign = */		ssh_rsa_sign,
	/* .verify = */		ssh_rsa_verify,
};

const struct sshkey_impl sshkey_rsa_impl = {
	/* .name = */		"ssh-rsa",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_cert_impl = {
	/* .name = */		"ssh-rsa-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

/* SHA2 signature algorithms */

const struct sshkey_impl sshkey_rsa_sha256_impl = {
	/* .name = */		"rsa-sha2-256",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha512_impl = {
	/* .name = */		"rsa-sha2-512",
	/* .shortname = */	"RSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_RSA,
	/* .nid = */		0,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha256_cert_impl = {
	/* .name = */		"rsa-sha2-256-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-256",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};

const struct sshkey_impl sshkey_rsa_sha512_cert_impl = {
	/* .name = */		"rsa-sha2-512-cert-v01@openssh.com",
	/* .shortname = */	"RSA-CERT",
	/* .sigalg = */		"rsa-sha2-512",
	/* .type = */		KEY_RSA_CERT,
	/* .nid = */		0,
	/* .cert = */		1,
	/* .sigonly = */	1,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_rsa_funcs,
};
#endif /* WITH_BEARSSL */
