/* $OpenBSD: ssh-ecdsa-sk.c,v 1.19 2024/08/15 00:51:51 djm Exp $ */
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
#include "misc.h"

#ifndef WITH_BEARSSL
/* ARGSUSED */
int
ssh_ecdsa_sk_verify(const struct sshkey *key,
    const u_char *signature, size_t signaturelen,
    const u_char *data, size_t datalen, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	return SSH_ERR_FEATURE_UNSUPPORTED;
}
#else /* WITH_BEARSSL */

/* Reuse some ECDSA internals */
extern struct sshkey_impl_funcs sshkey_ecdsa_funcs;

static void
ssh_ecdsa_sk_cleanup(struct sshkey *k)
{
	sshkey_sk_cleanup(k);
	sshkey_ecdsa_funcs.cleanup(k);
}

static int
ssh_ecdsa_sk_equal(const struct sshkey *a, const struct sshkey *b)
{
	if (!sshkey_sk_fields_equal(a, b))
		return 0;
	if (!sshkey_ecdsa_funcs.equal(a, b))
		return 0;
	return 1;
}

static int
ssh_ecdsa_sk_serialize_public(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if ((r = sshkey_ecdsa_funcs.serialize_public(key, b, opts)) != 0)
		return r;
	if ((r = sshkey_serialize_sk(key, b)) != 0)
		return r;

	return 0;
}

static int
ssh_ecdsa_sk_serialize_private(const struct sshkey *key, struct sshbuf *b,
    enum sshkey_serialize_rep opts)
{
	int r;

	if (!sshkey_is_cert(key)) {
		if ((r = sshkey_ecdsa_funcs.serialize_public(key,
		    b, opts)) != 0)
			return r;
	}
	if ((r = sshkey_serialize_private_sk(key, b)) != 0)
		return r;

	return 0;
}

static int
ssh_ecdsa_sk_copy_public(const struct sshkey *from, struct sshkey *to)
{
	int r;

	if ((r = sshkey_ecdsa_funcs.copy_public(from, to)) != 0)
		return r;
	if ((r = sshkey_copy_public_sk(from, to)) != 0)
		return r;
	return 0;
}

static int
ssh_ecdsa_sk_deserialize_public(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;

	if ((r = sshkey_ecdsa_funcs.deserialize_public(ktype, b, key)) != 0)
		return r;
	if ((r = sshkey_deserialize_sk(b, key)) != 0)
		return r;
	return 0;
}

static int
ssh_ecdsa_sk_deserialize_private(const char *ktype, struct sshbuf *b,
    struct sshkey *key)
{
	int r;

	if (!sshkey_is_cert(key)) {
		if ((r = sshkey_ecdsa_funcs.deserialize_public(ktype,
		    b, key)) != 0)
			return r;
	}
	if ((r = sshkey_private_deserialize_sk(b, key)) != 0)
		return r;

	return 0;
}

/*
 * Check FIDO/W3C webauthn signatures clientData field against the expected
 * format and prepare a hash of it for use in signature verification.
 *
 * webauthn signatures do not sign the hash of the message directly, but
 * instead sign a JSON-like "clientData" wrapper structure that contains the
 * message hash along with a other information.
 *
 * Fortunately this structure has a fixed format so it is possible to verify
 * that the hash of the signed message is present within the clientData
 * structure without needing to implement any JSON parsing.
 */
static int
webauthn_check_prepare_hash(const u_char *data, size_t datalen,
    const char *origin, const struct sshbuf *wrapper,
    uint8_t flags, const struct sshbuf *extensions,
    u_char *msghash, size_t msghashlen)
{
	int r = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *chall = NULL, *m = NULL;

	if ((m = sshbuf_new()) == NULL ||
	    (chall = sshbuf_from(data, datalen)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	/*
	 * Ensure origin contains no quote character and that the flags are
	 * consistent with what we received
	 */
	if (strchr(origin, '\"') != NULL ||
	    (flags & 0x40) != 0 /* AD */ ||
	    ((flags & 0x80) == 0 /* ED */) != (sshbuf_len(extensions) == 0)) {
		r = SSH_ERR_INVALID_FORMAT;
		goto out;
	}

	/*
	 * Prepare the preamble to clientData that we expect, poking the
	 * challenge and origin into their canonical positions in the
	 * structure. The crossOrigin flag and any additional extension
	 * fields present are ignored.
	 */
#define WEBAUTHN_0	"{\"type\":\"webauthn.get\",\"challenge\":\""
#define WEBAUTHN_1	"\",\"origin\":\""
#define WEBAUTHN_2	"\""
	if ((r = sshbuf_put(m, WEBAUTHN_0, sizeof(WEBAUTHN_0) - 1)) != 0 ||
	    (r = sshbuf_dtourlb64(chall, m, 0)) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_1, sizeof(WEBAUTHN_1) - 1)) != 0 ||
	    (r = sshbuf_put(m, origin, strlen(origin))) != 0 ||
	    (r = sshbuf_put(m, WEBAUTHN_2, sizeof(WEBAUTHN_2) - 1)) != 0)
		goto out;
#ifdef DEBUG_SK
	fprintf(stderr, "%s: received origin: %s\n", __func__, origin);
	fprintf(stderr, "%s: received clientData:\n", __func__);
	sshbuf_dump(wrapper, stderr);
	fprintf(stderr, "%s: expected clientData premable:\n", __func__);
	sshbuf_dump(m, stderr);
#endif
	/* Check that the supplied clientData has the preamble we expect */
	if ((r = sshbuf_cmp(wrapper, 0, sshbuf_ptr(m), sshbuf_len(m))) != 0)
		goto out;

	/* Prepare hash of clientData */
	if ((r = ssh_digest_buffer(SSH_DIGEST_SHA256, wrapper,
	    msghash, msghashlen)) != 0)
		goto out;

	/* success */
	r = 0;
 out:
	sshbuf_free(chall);
	sshbuf_free(m);
	return r;
}

static int
ssh_ecdsa_sk_verify(const struct sshkey *key,
    const u_char *sig, size_t siglen,
    const u_char *data, size_t dlen, const char *alg, u_int compat,
    struct sshkey_sig_details **detailsp)
{
	u_char rawsig[132];	/* maximum ECDSA signature length */
	size_t rslen;
	const u_char *sig_r = NULL, *sig_s = NULL;
	size_t sig_rlen, sig_slen;
	u_char sig_flags;
	u_char msghash[32], apphash[32], sighash[32];
	u_int sig_counter;
	int is_webauthn = 0, ret = SSH_ERR_INTERNAL_ERROR;
	struct sshbuf *b = NULL, *sigbuf = NULL, *original_signed = NULL;
	struct sshbuf *webauthn_wrapper = NULL, *webauthn_exts = NULL;
	char *ktype = NULL, *webauthn_origin = NULL;
	struct sshkey_sig_details *details = NULL;
#ifdef DEBUG_SK
	char *tmp = NULL;
#endif

	if (detailsp != NULL)
		*detailsp = NULL;
	if (key == NULL || key->ecdsa_pk == NULL ||
	    sshkey_type_plain(key->type) != KEY_ECDSA_SK ||
	    sig == NULL || siglen == 0)
		return SSH_ERR_INVALID_ARGUMENT;

	if (key->ecdsa_nid != BR_EC_secp256r1)
		return SSH_ERR_INTERNAL_ERROR;

	/* fetch signature */
	if ((b = sshbuf_from(sig, siglen)) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((details = calloc(1, sizeof(*details))) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (sshbuf_get_cstring(b, &ktype, NULL) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (strcmp(ktype, "webauthn-sk-ecdsa-sha2-nistp256@openssh.com") == 0)
		is_webauthn = 1;
	else if (strcmp(ktype, "sk-ecdsa-sha2-nistp256@openssh.com") != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (sshbuf_froms(b, &sigbuf) != 0 ||
	    sshbuf_get_u8(b, &sig_flags) != 0 ||
	    sshbuf_get_u32(b, &sig_counter) != 0) {
		ret = SSH_ERR_INVALID_FORMAT;
		goto out;
	}
	if (is_webauthn) {
		if (sshbuf_get_cstring(b, &webauthn_origin, NULL) != 0 ||
		    sshbuf_froms(b, &webauthn_wrapper) != 0 ||
		    sshbuf_froms(b, &webauthn_exts) != 0) {
			ret = SSH_ERR_INVALID_FORMAT;
			goto out;
		}
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

#ifdef DEBUG_SK
	fprintf(stderr, "%s: data: (len %zu)\n", __func__, dlen);
	/* sshbuf_dump_data(data, datalen, stderr); */
	fprintf(stderr, "%s: sig_r: %s\n", __func__, (tmp = BN_bn2hex(sig_r)));
	free(tmp);
	fprintf(stderr, "%s: sig_s: %s\n", __func__, (tmp = BN_bn2hex(sig_s)));
	free(tmp);
	fprintf(stderr, "%s: sig_flags = 0x%02x, sig_counter = %u\n",
	    __func__, sig_flags, sig_counter);
	if (is_webauthn) {
		fprintf(stderr, "%s: webauthn origin: %s\n", __func__,
		    webauthn_origin);
		fprintf(stderr, "%s: webauthn_wrapper:\n", __func__);
		sshbuf_dump(webauthn_wrapper, stderr);
	}
#endif
	rslen = MAXIMUM(sig_rlen, sig_slen) * 2;
	memset(rawsig, 0, rslen / 2 - sig_rlen);
	memcpy(rawsig + (rslen / 2 - sig_rlen), sig_r, sig_rlen);
	memset(rawsig + rslen / 2, 0, rslen / 2 - sig_slen);
	memcpy(rawsig + (rslen - sig_slen), sig_s, sig_slen);

	/* Reconstruct data that was supposedly signed */
	if ((original_signed = sshbuf_new()) == NULL) {
		ret = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (is_webauthn) {
		if ((ret = webauthn_check_prepare_hash(data, dlen,
		    webauthn_origin, webauthn_wrapper, sig_flags, webauthn_exts,
		    msghash, sizeof(msghash))) != 0)
			goto out;
	} else if ((ret = ssh_digest_memory(SSH_DIGEST_SHA256, data, dlen,
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
	    (ret = sshbuf_putb(original_signed, webauthn_exts)) != 0 ||
	    (ret = sshbuf_put(original_signed, msghash, sizeof(msghash))) != 0)
		goto out;
	/* Signature is over H(original_signed) */
	if ((ret = ssh_digest_buffer(SSH_DIGEST_SHA256, original_signed,
	    sighash, sizeof(sighash))) != 0)
		goto out;
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
	    sizeof(sighash), &key->ecdsa_pk->key, rawsig, rslen) != 1) {
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
	explicit_bzero(sighash, sizeof(sighash));
	explicit_bzero(apphash, sizeof(apphash));
	sshkey_sig_details_free(details);
	sshbuf_free(webauthn_wrapper);
	sshbuf_free(webauthn_exts);
	free(webauthn_origin);
	sshbuf_free(original_signed);
	sshbuf_free(sigbuf);
	sshbuf_free(b);
	explicit_bzero(rawsig, sizeof(rawsig));
	free(ktype);
	return ret;
}

static const struct sshkey_impl_funcs sshkey_ecdsa_sk_funcs = {
	/* .size = */		NULL,
	/* .alloc = */		NULL,
	/* .cleanup = */	ssh_ecdsa_sk_cleanup,
	/* .equal = */		ssh_ecdsa_sk_equal,
	/* .ssh_serialize_public = */ ssh_ecdsa_sk_serialize_public,
	/* .ssh_deserialize_public = */ ssh_ecdsa_sk_deserialize_public,
	/* .ssh_serialize_private = */ ssh_ecdsa_sk_serialize_private,
	/* .ssh_deserialize_private = */ ssh_ecdsa_sk_deserialize_private,
	/* .generate = */	NULL,
	/* .copy_public = */	ssh_ecdsa_sk_copy_public,
	/* .sign = */		NULL,
	/* .verify = */		ssh_ecdsa_sk_verify,
};

const struct sshkey_impl sshkey_ecdsa_sk_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_SK,
	/* .nid = */		BR_EC_secp256r1,
	/* .cert = */		0,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

const struct sshkey_impl sshkey_ecdsa_sk_cert_impl = {
	/* .name = */		"sk-ecdsa-sha2-nistp256-cert-v01@openssh.com",
	/* .shortname = */	"ECDSA-SK-CERT",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_SK_CERT,
	/* .nid = */		BR_EC_secp256r1,
	/* .cert = */		1,
	/* .sigonly = */	0,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

const struct sshkey_impl sshkey_ecdsa_sk_webauthn_impl = {
	/* .name = */		"webauthn-sk-ecdsa-sha2-nistp256@openssh.com",
	/* .shortname = */	"ECDSA-SK",
	/* .sigalg = */		NULL,
	/* .type = */		KEY_ECDSA_SK,
	/* .nid = */		BR_EC_secp256r1,
	/* .cert = */		0,
	/* .sigonly = */	1,
	/* .keybits = */	256,
	/* .funcs = */		&sshkey_ecdsa_sk_funcs,
};

#endif /* WITH_BEARSSL */
