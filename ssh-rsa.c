/* $OpenBSD: ssh-rsa.c,v 1.67 2018/07/03 11:39:54 djm Exp $ */
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
#include "compat.h"
#include "ssherr.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"
#include "digest.h"
#include "log.h"

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
int
ssh_rsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, const char *alg_ident)
{
	u_char digest[SSH_DIGEST_MAX_LENGTH], *sig = NULL;
	size_t slen = 0;
	u_int dlen, len;
	int hash_alg, ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL;
	const u_char *oid;

	if (lenp != NULL)
		*lenp = 0;
	if (sigp != NULL)
		*sigp = NULL;

	if (alg_ident == NULL || strlen(alg_ident) == 0)
		hash_alg = SSH_DIGEST_SHA1;
	else
		hash_alg = rsa_hash_id_from_keyname(alg_ident);
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
	if ((dlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if ((sig = malloc(slen)) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if (br_rsa_pkcs1_sign_get_default()(oid, digest, dlen,
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

int
ssh_rsa_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen, const u_char *data, size_t datalen,
    const char *alg)
{
	char *sigtype = NULL;
	int hash_alg, want_alg, ret = SSH_ERR_INTERNAL_ERROR;
	size_t len = 0, dlen;
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
	if ((dlen = ssh_digest_bytes(hash_alg)) == 0) {
		ret = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if (br_rsa_pkcs1_vrfy_get_default()(sigblob, len, oid, dlen,
	    &key->rsa_pk->key, sigdigest) != 1 ||
	    timingsafe_bcmp(digest, sigdigest, dlen) != 0) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
 out:
	free(sigtype);
	sshbuf_free(b);
	explicit_bzero(digest, sizeof(digest));
	explicit_bzero(sigdigest, sizeof(sigdigest));
	return ret;
}
#endif /* WITH_BEARSSL */
