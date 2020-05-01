/* $OpenBSD: kexecdh.c,v 1.10 2019/01/21 10:40:11 djm Exp $ */
/*
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2019 Markus Friedl.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include <bearssl.h>

#include "sshkey.h"
#include "kex.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

static int
kex_ecdh_dec_key_group(struct kex *, const struct sshbuf *,
    const struct sshkey_ecdsa_sk *key, struct sshbuf **);

int
kex_ecdh_keypair(struct kex *kex)
{
	const br_prng_class *rng = &arc4random_prng;
	struct sshkey_ecdsa_sk *client_key = NULL;
	struct sshkey_ecdsa_pk public_key;
	struct sshbuf *buf = NULL;
	int r;

	if ((client_key = calloc(1, sizeof(*client_key))) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if (br_ec_keygen(&rng, br_ec_get_default(), &client_key->key,
	    client_key->data, kex->ec_nid) == 0 ||
	    br_ec_compute_pub(br_ec_get_default(), &public_key.key,
	    public_key.data, &client_key->key) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put(buf, public_key.key.q, public_key.key.qlen)) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	fputs("client private key:\n", stderr);
	sshkey_dump_ec_key(client_key);
#endif
	kex->ec_client_key = client_key;
	client_key = NULL;	/* owned by the kex */
	kex->client_pub = buf;
	buf = NULL;
 out:
	freezero(client_key, sizeof(*client_key));
	explicit_bzero(&public_key, sizeof(public_key));
	sshbuf_free(buf);
	return r;
}

int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	const br_prng_class *rng = &arc4random_prng;
	struct sshkey_ecdsa_sk server_key;
	struct sshkey_ecdsa_pk public_key;
	struct sshbuf *server_blob = NULL;
	int r;

	*server_blobp = NULL;
	*shared_secretp = NULL;

	if (br_ec_keygen(&rng, br_ec_get_default(), &server_key.key,
	    server_key.data, kex->ec_nid) == 0 ||
	    br_ec_compute_pub(br_ec_get_default(), &public_key.key,
	    public_key.data, &server_key.key) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}

#ifdef DEBUG_KEXECDH
	fputs("server private key:\n", stderr);
	sshkey_dump_ec_key(server_key);
#endif
	if ((server_blob = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put(server_blob, public_key.key.q,
	    public_key.key.qlen)) != 0)
		goto out;
	if ((r = kex_ecdh_dec_key_group(kex, client_blob, &server_key,
	    shared_secretp)) != 0)
		goto out;
	*server_blobp = server_blob;
	server_blob = NULL;
 out:
	explicit_bzero(&server_key, sizeof(server_key));
	explicit_bzero(&public_key, sizeof(public_key));
	sshbuf_free(server_blob);
	return r;
}

static int
kex_ecdh_dec_key_group(struct kex *kex, const struct sshbuf *ec_blob,
    const struct sshkey_ecdsa_sk *key, struct sshbuf **shared_secretp)
{
	const br_ec_impl *ec;
	struct sshbuf *buf = NULL;
	u_char kbuf[BR_EC_KBUF_PUB_MAX_SIZE];
	size_t klen, xoff, xlen;
	int r;

	*shared_secretp = NULL;

	if ((klen = sshbuf_len(ec_blob)) > sizeof(kbuf)) {
		r = SSH_ERR_NO_BUFFER_SPACE;
		goto out;
	}
	memcpy(kbuf, sshbuf_ptr(ec_blob), klen);

#ifdef DEBUG_KEXECDH
	fputs("public key:\n", stderr);
	sshkey_dump_ec_point(group, dh_pub);
#endif
	if (sshkey_ec_validate_public(key->key.curve, kbuf, klen) != 0) {
		r = SSH_ERR_MESSAGE_INCOMPLETE;
		goto out;
	}

	ec = br_ec_get_default();
	if ((ec->supported_curves & 1 << key->key.curve) == 0 ||
	    ec->mul(kbuf, klen, key->key.x, key->key.xlen,
	    key->key.curve) == 0) {
		r = SSH_ERR_LIBCRYPTO_ERROR;
		goto out;
	}
	xoff = ec->xoff(key->key.curve, &xlen);
#ifdef DEBUG_KEXECDH
	dump_digest("shared secret", kbuf, klen);
#endif
	if ((buf = sshbuf_new()) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}
	if ((r = sshbuf_put_bignum2_bytes(buf, kbuf + xoff, xlen)) != 0)
		goto out;
	*shared_secretp = buf;
	buf = NULL;
 out:
	explicit_bzero(kbuf, sizeof(kbuf));
	sshbuf_free(buf);
	return r;
}

int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	int r;

	r = kex_ecdh_dec_key_group(kex, server_blob, kex->ec_client_key,
	    shared_secretp);
	freezero(kex->ec_client_key, sizeof(*kex->ec_client_key));
	kex->ec_client_key = NULL;
	return r;
}

#else

#include "ssherr.h"

struct kex;
struct sshbuf;
struct sshkey;

int
kex_ecdh_keypair(struct kex *kex)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_ecdh_enc(struct kex *kex, const struct sshbuf *client_blob,
    struct sshbuf **server_blobp, struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}

int
kex_ecdh_dec(struct kex *kex, const struct sshbuf *server_blob,
    struct sshbuf **shared_secretp)
{
	return SSH_ERR_SIGN_ALG_UNSUPPORTED;
}
#endif /* !WITH_BEARSSL */
