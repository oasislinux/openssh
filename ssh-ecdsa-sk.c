/* $OpenBSD: ssh-ecdsa-sk.c,v 1.5 2019/11/26 03:04:27 djm Exp $ */
/*
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2019 Google Inc.  All rights reserved.
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

/* #define DEBUG_SK 1 */

#include "includes.h"

#include <sys/types.h>

#ifdef WITH_BEARSSL
#include <bearssl.h>
#endif

#include <stdio.h> /* needed for DEBUG_SK only */
#include <stdlib.h>
#include <string.h>

#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"
#define SSHKEY_INTERNAL
#include "sshkey.h"

/* ARGSUSED */
int
ssh_ecdsa_sk_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	u_char sig[132];	/* maximum ECDSA signature length */
	size_t slen;
	const u_char *sig_r = NULL, *sig_s = NULL;
	size_t sig_rlen, sig_slen;
	u_char sig_flags;
	u_char msghash[32], apphash[32], sighash[32];
	u_int sig_counter;
	int ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *sigbuf = NULL, *original_signed = NULL;
	char *ktype = NULL;
	struct sshkey_sig_details *details = NULL;
#ifdef DEBUG_SK
	char *tmp = NULL;
#endif

	if (detailsp != NULL)
		*detailsp = NULL;
	if (key == NULL || key->ecdsa_pk == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA_SK ||
	    signature == NULL || signaturelen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if (key->ecdsa_nid != BR_EC_secp256r1)
		return SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	if ((b = sshbuf_from(signature, signaturelen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0 ||
	    sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
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
	memcpy(sig, sig_r, sig_rlen);
	if (sig_rlen < sig_slen) {
		memmove(sig, sig + (sig_slen - sig_rlen), sig_rlen);
		memset(sig, 0, sig_slen - sig_rlen);
		sig_rlen = sig_slen;
	}
	memset(sig + sig_rlen, 0, sig_rlen - sig_slen);
	memcpy(sig + sig_rlen + (sig_rlen - sig_slen), sig_s, sig_slen);
	slen = sig_rlen * 2;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, datalen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	free(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	free(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
#endif
	sig_r = sig_s = NULL; /* transferred */

	if (sshbuf_len(sigbuf) != 0) {
		ret = SSH_ERR_UNEXPECTED_TRAILING_DATA;
		goto out;
	}

	/* Reconstruct data that was supposedly signed */
	if ((original_signed = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, data, datalen,
	    msghash, sizeof(msghash))) != 0)
		goto out;
	/* Application value is hashed before signature */
	if ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, key->sk_application,
	    strlen(key->sk_application), apphash, sizeof(apphash))) != 0)
		goto out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: hashed application:\n", __func__);
	sshbuf_dump_data(apphash, sizeof(apphash), stderr);
	fprintf(stderr, "%s: hashed message:\n", __func__);
	sshbuf_dump_data(msghash, sizeof(msghash), stderr);
#endif
	if ((ret = sshbuf_put(original_signed,
	    apphash, sizeof(apphash))) != 0 ||
	    (ret = sshbuf_put_u8(original_signed, sig_flags)) != 0 ||
	    (ret = sshbuf_put_u32(original_signed, sig_counter)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, sizeof(msghash))) != 0)
		goto out;
	/* Signature is over H(original_signed) */
	if ((ret = ssh_digest_buffer(SSH_DIGEST_SHA256, original_signed,
	    sighash, sizeof(sighash))) != 0)
		goto out;
	if ((details = calloc(1, sizeof(*details))) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	details->sk_counter = sig_counter;
	details->sk_flags = sig_flags;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: signed buf:\n", __func__);
	sshbuf_dump(original_signed, stderr);
	fprintf(stderr, "%s: signed hash:\n", __func__);
	sshbuf_dump_data(sighash, sizeof(sighash), stderr);
#endif

	/* Verify it */
	if (br_ecdsa_vrfy_raw_get_default()(br_ec_get_default(), sighash,
	    sizeof(sighash), &key->ecdsa_pk->key, sig, slen) != 1) {
		ret = SSH_ERR_SIGNATURE_INVALID;
		goto out;
	}
	/* success */
	if (detailsp != NULL) {
		*detailsp = details;
		details = NULL;
	}
 out:
	explicit_bzero(&sig_flags, sizeof(sig_flags));
	explicit_bzero(&sig_counter, sizeof(sig_counter));
	explicit_bzero(msghash, sizeof(msghash));
	explicit_bzero(sighash, sizeof(msghash));
	explicit_bzero(apphash, sizeof(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	explicit_bzero(sig, sizeof(sig));
	free(ktype);
	return ret;
}
