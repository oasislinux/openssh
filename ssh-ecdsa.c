/* $OpenBSD: ssh-ecdsa.c,v 1.16 2019/01/21 09:54:11 djm Exp $ */
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

/* ARGSUSED */
int
ssh_ecdsa_sign(const struct sshkey *key, u_char **sigp, size_t *lenp,
    const u_char *data, size_t datalen, u_int compat)
{
	int hash_alg;
	const br_hash_class *hash_class = NULL;
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	u_char sig[132];	/* maximum ECDSA signature length */
	size_t len, slen;
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
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
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

	if ((slen = br_ecdsa_sign_raw_get_default()(br_ec_get_default(),
	    hash_class, digest, &key->ecdsa_sk->key, sig)) == 0 ||
	    slen % 2 != 0) {
		ret = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((bb = sshbuf_new()) == NULL || (b = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = sshbuf_put_bignum2_bytes(bb, sig, slen / 2)) != 0 ||
	    (ret = sshbuf_put_bignum2_bytes(bb, sig + slen / 2, slen / 2)) != 0)
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

/* ARGSUSED */
int
ssh_ecdsa_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat)
{
	u_char sig[132];	/* maximum ECDSA signature length */
	size_t slen;
	const u_char *sig_r = NULL, *sig_s = NULL;
	size_t sig_rlen, sig_slen;
	int hash_alg;
	u_char digest[SSH_DIGEST_MAX_LENGTH];
	size_t dlen;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *sigbuf = NULL;
	char *ktype = NULL;

	if (key == NULL || key->ecdsa_pk == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if ((hash_alg = sshkey_ec_nid_to_hash_alg(key->ecdsa_nid)) == -1 ||
	    (dlen = ssh_digest_bytes(hash_alg)) == 0)
		return SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
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
	    sig_rlen > sizeof(sig) / 2 || sig_slen > sizeof(sig) / 2) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	slen = MAXIMUM(sig_rlen, sig_slen) * 2;
	memset(sig, 0, slen / 2 - sig_rlen);
	memcpy(sig + (slen / 2 - sig_rlen), sig_r, sig_rlen);
	memset(sig + slen / 2, 0, slen / 2 - sig_slen);
	memcpy(sig + (slen - sig_slen), sig_s, sig_slen);

	if (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}
	if ((ret = ssh_digest_memory(hash_alg, data, datalen,
	    digest, sizeof(digest))) != 0)
		goto out;

	if (br_ecdsa_vrfy_raw_get_default()(br_ec_get_default(), digest, dlen,
	    &key->ecdsa_pk->key, sig, slen) != 1) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}

 out:
	explicit_bzero(sig, sizeof(sig));
	explicit_bzero(digest, sizeof(digest));
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	free(ktype);
	return ret;
}

#endif /* WITH_BEARSSL */
