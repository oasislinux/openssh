/* $OpenBSD: ssh-ecdsa.c,v 1.27 2024/08/15 00:51:51 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "includes.h"

#ifdef WITH_BEARSSL

#include <sys/types.h>

#include <bearssl.h>

#include <stdlib.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "misc.h"

static u_int
ssh_ecdsa_size(const struct sshkey *key)
{
	switch (key->ecdsa_nid) {
	case BR_EC_secp256r1:
		return 256;
	case BR_EC_secp384r1:
		return 384;
	case BR_EC_secp521r1:
		return 521;
	default:
		return 0;
	}
}

static void
ssh_ecdsa_cleanup(struct sshkey *k)
{
	freezero(k->ecdsa_pk, sizeof(*k->ecdsa_pk));
	k->ecdsa_pk = NULL;
	freezero(k->ecdsa_sk, sizeof(*k->ecdsa_sk));
	k->ecdsa_sk = NULL;
}

static int
ssh_ecdsa_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (a->ecdsa_pk == NULL || b->ecdsa_pk == NULL)
		return 0;
	if (a->ecdsa_pk->key.curve != b->ecdsa_pk->key.curve)
		return 0;
	if (a->ecdsa_pk->key.qlen != b->ecdsa_pk->key.qlen)
		return 0;
	if (memcmp(a->ecdsa_pk->key.q, b->ecdsa_pk->key.q,
	    a->ecdsa_pk->key.qlen) != 0)
		return 0;

	return 1;
}

static int
ssh_ecdsa_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if (key->ecdsa_pk == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshbuf_put_cstring(b,
	    sshkey_curve_nid_to_name(key->ecdsa_nid))) != 0 ||
	    (r = sshbuf_put_ec_bytes(b, key->ecdsa_pk->key.q,
	    key->ecdsa_pk->key.qlen)) != 0)
		return r;

	return 0;
}

static int
ssh_ecdsa_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if (!sshkey_is_cert(key)) {
		if ((r = ssh_ecdsa_serialize_public(key, b, opts)) != 0)
			return r;
	}
	if ((r = sshbuf_put_bignum2_bytes(b, key->ecdsa_sk->key.x,
	    key->ecdsa_sk->key.xlen)) != 0)
		return r;
	return 0;
}

static int
ssh_ecdsa_generate(struct sshkey *k, int bits)
{
	struct sshkey_ecdsa_pk *ecdsa_pk = NULL;
	struct sshkey_ecdsa_sk *ecdsa_sk = NULL;
	const br_prng_class *rng = &arc4random_prng;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if ((k->ecdsa_nid = sshkey_ecdsa_bits_to_nid(bits)) == -1)
		return SSH_ERR_KEY_LENGTH;
	if ((ecdsa_pk = calloc(1, sizeof(*ecdsa_pk))) == NULL ||
	    (ecdsa_sk = calloc(1, sizeof(*ecdsa_sk))) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (br_ec_keygen(&rng, br_ec_get_default(), &ecdsa_sk->key,
	    ecdsa_sk->data, k->ecdsa_nid) == 0 ||
	    br_ec_compute_pub(br_ec_get_default(), &ecdsa_pk->key,
	    ecdsa_pk->data, &ecdsa_sk->key) == 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	/* success */
	k->ecdsa_pk = ecdsa_pk;
	ecdsa_pk = NULL;
	k->ecdsa_sk = ecdsa_sk;
	ecdsa_sk = NULL;
	ret = 0;
 out:
	freezero(ecdsa_pk, sizeof(*ecdsa_pk));
	freezero(ecdsa_sk, sizeof(*ecdsa_sk));
	return ret;
}

static int
ssh_ecdsa_copy_public(const struct sshkey *from, struct sshkey *to)
{
	struct sshkey_ecdsa_pk *ecdsa_pk;

	if ((ecdsa_pk = calloc(1, sizeof(*ecdsa_pk))) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	ecdsa_pk->key.curve = from->ecdsa_pk->key.curve;
	ecdsa_pk->key.q = ecdsa_pk->data;
	ecdsa_pk->key.qlen = from->ecdsa_pk->key.qlen;
	memcpy(ecdsa_pk->key.q, from->ecdsa_pk->key.q, from->ecdsa_pk->key.qlen);

	to->ecdsa_nid = from->ecdsa_nid;
	to->ecdsa_pk = ecdsa_pk;
	return 0;
}

static int
ssh_ecdsa_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;
	char *curve = NULL;
	struct sshkey_ecdsa_pk *ecdsa_pk = NULL;
	int ecdsa_nid;
	const u_char *ecdsa_q;
	size_t ecdsa_qlen;

	if ((ecdsa_nid = sshkey_ecdsa_nid_from_name(ktype)) == -1)
		return SSH_ERR_INVALID_ARGUMENT;
	if ((r = sshbuf_get_cstring(b, &curve, NULL)) != 0)
		goto out;
	if (ecdsa_nid != sshkey_curve_name_to_nid(curve)) {
		r = SSH_ERR_EC_CURVE_MISMATCH;
		goto out;
	}
	if ((ecdsa_pk = calloc(1, sizeof(*ecdsa_pk))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_get_ec_bytes_direct(b, &ecdsa_q, &ecdsa_qlen)) != 0)
		goto out;
	if (ecdsa_qlen > sizeof(ecdsa_pk->data)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ecdsa_pk->key.curve = ecdsa_nid;
	ecdsa_pk->key.q = ecdsa_pk->data;
	ecdsa_pk->key.qlen = ecdsa_qlen;
	memcpy(ecdsa_pk->key.q, ecdsa_q, ecdsa_qlen);
	if (sshkey_ec_validate_public(ecdsa_nid, ecdsa_q,
	    ecdsa_qlen) != 0) {
		r = SSH_ERR_KEY_INVALID_EC_VALUE;
		goto out;
	}

	/* success */
	key->ecdsa_nid = ecdsa_nid;
	key->ecdsa_pk = ecdsa_pk;
	ecdsa_pk = NULL;
	r = 0;
#ifdef DEBUG_PK
	/* XXX */
#endif
 out:
	freezero(ecdsa_pk, sizeof(*key->ecdsa_pk));
	free(curve);
	return r;
}

static int
ssh_ecdsa_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;
	struct sshkey_ecdsa_sk *ecdsa_sk = NULL;
	const u_char *ecdsa_x;
	size_t ecdsa_xlen;

	if (!sshkey_is_cert(key)) {
		if ((r = ssh_ecdsa_deserialize_public(ktype, b, key)) != 0)
			return r;
	}

	if ((ecdsa_sk = calloc(1, sizeof(*ecdsa_sk))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_get_bignum2_bytes_direct(b, &ecdsa_x, &ecdsa_xlen)) != 0)
		goto out;
	if (ecdsa_xlen > sizeof(ecdsa_sk->data)) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	ecdsa_sk->key.curve = key->ecdsa_pk->key.curve;
	ecdsa_sk->key.x = ecdsa_sk->data;
	ecdsa_sk->key.xlen = ecdsa_xlen;
	memcpy(ecdsa_sk->key.x, ecdsa_x, ecdsa_xlen);
	if ((r = sshkey_ec_validate_private(ecdsa_sk->key.curve,
	    ecdsa_sk->key.x, ecdsa_sk->key.xlen)) != 0)
		goto out;
	/* success */
	key->ecdsa_sk = ecdsa_sk;
	ecdsa_sk = NULL;
	r = 0;
 out:
	freezero(ecdsa_sk, sizeof(*ecdsa_sk));
	return r;
}

static int
ssh_ecdsa_sign(struct sshkey *key,
    u_char **sigp, size_t *lenp,
    const u_char *data, size_t dlen,
    const char *alg, const char *sk_provider, const char *sk_pin, u_int compat)
{
	int hash_alg;
	const br_hash_class *hash_class = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	u_char rawsig[132];	/* maximum ECDSA signature length */
	size_t len, rslen;
	struct sshbuf *b = NULL, *bb = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (key == NULL || key->ecdsa_sk == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1)
		return SSH_ERR_INTERNAL_ERROR;
	if ((ret = ssh_digest_memory(hash_alg, data, dlen,
	    digest, sizeof(digest))) != 0)
		goto out;

	switch (hash_alg) {
	case SSH_DIGEST_SHA256:
		hash_class = &br_sha256_vtable;
		break;
	case SSH_DIGEST_SHA384:
		hash_class = &br_sha384_vtable;
		break;
	case SSH_DIGEST_SHA512:
		hash_class = &br_sha512_vtable;
		break;
	default:
		return SSH_ERR_INTERNAL_ERROR;
	}

	if ((rslen = br_ecdsa_sign_raw_get_default()(br_ec_get_default(),
	    hash_class, digest, &key->ecdsa_sk->key, rawsig)) == 0 ||
	    rslen % 2 != 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	if ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_bignum2_bytes(bb, rawsig, rslen / 2)) != 0 ||
	    (ret = sshbuf_put_bignum2_bytes(bb, rawsig + rslen / 2, rslen / 2)) != 0)
		goto out;
	if ((ret = sshbuf_put_cstring(b, sshkey_ssh_name_plain(key))) != 0 ||
	    (ret = sshbuf_put_stringb(b, bb)) != 0)
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
	sshbuf_free(b);
	sshbuf_free(bb);
	return ret;
}

static int
ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	u_char rawsig[132];	/* maximum ECDSA signature length */
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	size_t rslen, digestlen;
	const u_char *sig_r = NULL, *sig_s = NULL;
	size_t sig_rlen, sig_slen;
	int hash_alg;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;

	if (key == NULL || key->ecdsa_pk == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1 ||
	    (digestlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp(sshkey_ssh_name_plain(key), ktype) != 0) {
		ret = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (sshbuf_len(b) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	/* parse signature */
	if (sshbuf_get_bignum2_bytes_direct(sigbuf, &sig_r, &sig_rlen) != 0 ||
	    sshbuf_get_bignum2_bytes_direct(sigbuf, &sig_s, &sig_slen) != 0 ||
	    sig_rlen > sizeof(rawsig) / 2 || sig_slen > sizeof(rawsig) / 2) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	rslen = MAXIMUM(sig_rlen, sig_slen) * 2;
	memset(rawsig, 0, rslen / 2 - sig_rlen);
	memcpy(rawsig + (rslen / 2 - sig_rlen), sig_r, sig_rlen);
	memset(rawsig + rslen / 2, 0, rslen / 2 - sig_slen);
	memcpy(rawsig + (rslen - sig_slen), sig_s, sig_slen);

	if (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if ((ret = ssh_digest_memory(hash_alg, data, dlen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if (br_ecdsa_vrfy_raw_get_default()(br_ec_get_default(), digest,
	    digestlen, &key->ecdsa_pk->key, rawsig, rslen) != 1) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	/* success */
	ret = 0;
 out:
	explicit_bzero(rawsig, sizeof(rawsig));
	explicit_bzero(digest, sizeof(digest));
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	free(ktype);
	return ret;
}

/* NB. not static; used by ECDSA-SK */
const struct sshkey_impl_funcs sshkey_ecdsa_funcs = {
	/* .size = */		ssh_ecdsa_size,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_ecdsa_cleanup,
	/* .equal = */		ssh_ecdsa_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_deserialize_private,
	/* .generate = */	ssh_ecdsa_generate,
	/* .copy_public = */	ssh_ecdsa_copy_public,
	/* .sign = */		ssh_ecdsa_sign,
	/* .verify = */		ssh_ecdsa_verify,
};

const struct sshkey_impl sshkey_ecdsa_nistp256_impl = {
	/* .name = */		"ecdsa-sha2-nistp256",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		BR_EC_secp256r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp256_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		BR_EC_secp256r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp384_impl = {
	/* .name = */		"ecdsa-sha2-nistp384",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		BR_EC_secp384r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp384_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp384-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		BR_EC_secp384r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp521_impl = {
	/* .name = */		"ecdsa-sha2-nistp521",
	/* .shortname = */	"ECDSA",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA,
	/* .nid = */		BR_EC_secp521r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

const struct sshkey_impl sshkey_ecdsa_nistp521_cert_impl = {
	/* .name = */		"ecdsa-sha2-nistp521-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_CERT,
	/* .nid = */		BR_EC_secp521r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	0,
	/* .funcs = */		&sshkey_ecdsa_funcs,
};

#endif /* WITH_BEARSSL */
