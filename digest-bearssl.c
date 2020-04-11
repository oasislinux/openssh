/* $OpenBSD: digest-bearssl.c,v 1.7 2017/05/08 22:57:38 djm Exp $ */
/*
 * Copyright (c) 2013 Damien Miller <djm@mindrot.org>
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
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <bearssl.h>

#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

struct ssh_digest_ctx {
	int alg;
	br_hash_compat_context hc;
};

struct ssh_digest {
	int id;
	const char *name;
	const br_hash_class *class;
};

/* NB. Indexed directly by algorithm number */
const struct ssh_digest digests[] = {
	{ SSH_DIGEST_MD5,	"MD5",	 	&br_md5_vtable },
	{ SSH_DIGEST_SHA1,	"SHA1",	 	&br_sha1_vtable },
	{ SSH_DIGEST_SHA256,	"SHA256", 	&br_sha256_vtable },
	{ SSH_DIGEST_SHA384,	"SHA384",	&br_sha384_vtable },
	{ SSH_DIGEST_SHA512,	"SHA512", 	&br_sha512_vtable },
	{ -1,			NULL,		NULL },
};

static const struct ssh_digest *
ssh_digest_by_alg(int alg)
{
	if (alg < 0 || alg >= SSH_DIGEST_MAX)
		return NULL;
	if (digests[alg].id != alg) /* sanity */
		return NULL;
	if (digests[alg].class == NULL)
		return NULL;
	return &(digests[alg]);
}

int
ssh_digest_alg_by_name(const char *name)
{
	int alg;

	for (alg = 0; digests[alg].id != -1; alg++) {
		if (strcasecmp(name, digests[alg].name) == 0)
			return digests[alg].id;
	}
	return -1;
}

const char *
ssh_digest_alg_name(int alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	return digest == NULL ? NULL : digest->name;
}

static size_t
hashdesc_out(uint32_t desc)
{
	return desc >> BR_HASHDESC_OUT_OFF & BR_HASHDESC_OUT_MASK;
}

static int
hashdesc_lblen(uint32_t desc)
{
	return desc >> BR_HASHDESC_LBLEN_OFF & BR_HASHDESC_LBLEN_MASK;
}

size_t
ssh_digest_bytes(int alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);

	return digest == NULL ? 0 : hashdesc_out(digest->class->desc);
}

size_t
ssh_digest_blocksize(struct ssh_digest_ctx *ctx)
{
	return 1 << hashdesc_lblen(ctx->hc.vtable->desc);
}

struct ssh_digest_ctx *
ssh_digest_start(int alg)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);
	struct ssh_digest_ctx *ret;

	if (digest == NULL || ((ret = calloc(1, sizeof(*ret))) == NULL))
		return NULL;
	ret->alg = alg;
	digest->class->init(&ret->hc.vtable);
	return ret;
}

int
ssh_digest_copy_state(struct ssh_digest_ctx *from, struct ssh_digest_ctx *to)
{
	uint64_t count;
	unsigned char state[64];

	if (from->alg != to->alg)
		return SSH_ERR_INVALID_ARGUMENT;
	count = from->hc.vtable->state(&from->hc.vtable, state);
	to->hc.vtable->set_state(&to->hc.vtable, state, count);
	return 0;
}

int
ssh_digest_update(struct ssh_digest_ctx *ctx, const void *m, size_t mlen)
{
	ctx->hc.vtable->update(&ctx->hc.vtable, m, mlen);
	return 0;
}

int
ssh_digest_update_buffer(struct ssh_digest_ctx *ctx, const struct sshbuf *b)
{
	return ssh_digest_update(ctx, sshbuf_ptr(b), sshbuf_len(b));
}

int
ssh_digest_final(struct ssh_digest_ctx *ctx, u_char *d, size_t dlen)
{
	/* No truncation allowed */
	if (dlen < hashdesc_out(ctx->hc.vtable->desc))
		return SSH_ERR_INVALID_ARGUMENT;
	ctx->hc.vtable->out(&ctx->hc.vtable, d);
	return 0;
}

void
ssh_digest_free(struct ssh_digest_ctx *ctx)
{
	if (ctx == NULL)
		return;
	freezero(ctx, sizeof(*ctx));
}

int
ssh_digest_memory(int alg, const void *m, size_t mlen, u_char *d, size_t dlen)
{
	const struct ssh_digest *digest = ssh_digest_by_alg(alg);
	br_hash_compat_context hc;

	if (digest == NULL)
		return SSH_ERR_INVALID_ARGUMENT;
	if (dlen < hashdesc_out(digest->class->desc))
		return SSH_ERR_INVALID_ARGUMENT;
	digest->class->init(&hc.vtable);
	hc.vtable->update(&hc.vtable, m, mlen);
	hc.vtable->out(&hc.vtable, d);
	return 0;
}

int
ssh_digest_buffer(int alg, const struct sshbuf *b, u_char *d, size_t dlen)
{
	return ssh_digest_memory(alg, sshbuf_ptr(b), sshbuf_len(b), d, dlen);
}
#endif /* WITH_BEARSSL */
