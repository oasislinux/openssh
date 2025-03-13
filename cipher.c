/* $OpenBSD: cipher.c,v 1.120 2023/10/10 06:49:54 tb Exp $ */
/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * Copyright (c) 1999 Niels Provos.  All rights reserved.
 * Copyright (c) 1999, 2000 Markus Friedl.  All rights reserved.
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

#include <sys/types.h>

#include <string.h>
#include <stdarg.h>
#include <stdio.h>

#ifdef WITH_BEARSSL
#include <bearssl.h>
#endif

#include "cipher.h"
#ifndef WITH_BEARSSL
#include "cipher-aesctr.h"
#endif
#include "cipher-chachapoly.h"
#include "misc.h"
#include "sshbuf.h"
#include "ssherr.h"
#include "digest.h"

struct sshcipher_ctx {
	int	plaintext;
	int	encrypt;
	struct chachapoly_ctx *cp_ctx;
#ifdef WITH_BEARSSL
	union {
		br_aes_ct64_cbcenc_keys cbcenc;
		br_aes_ct64_cbcdec_keys cbcdec;
		br_aes_ct64_ctr_keys ctr;
	} keys;
	br_gcm_context gcm;
	u_char iv[16];
#else
	struct aesctr_ctx ac_ctx;
#endif
	const struct sshcipher *cipher;
};

enum sshcipher_types {
	CIPHER_NONE,
	CIPHER_AESCBC,
	CIPHER_AESCTR,
	CIPHER_AESGCM,
	CIPHER_CHACHAPOLY,
};

struct sshcipher {
	char	*name;
	u_int	block_size;
	u_int	key_len;
	u_int	iv_len;		/* defaults to block_size */
	u_int	auth_len;
	u_int	type;
};

static const struct sshcipher ciphers[] = {
#ifdef WITH_BEARSSL
	{ "aes128-cbc",		16, 16, 16, 0, CIPHER_AESCBC },
	{ "aes192-cbc",		16, 24, 16, 0, CIPHER_AESCBC },
	{ "aes256-cbc",		16, 32, 16, 0, CIPHER_AESCBC },
	{ "aes128-gcm@openssh.com",
				16, 16, 12, 16, CIPHER_AESGCM },
	{ "aes256-gcm@openssh.com",
				16, 32, 12, 16, CIPHER_AESGCM },
#endif
	{ "aes128-ctr",		16, 16, 16, 0, CIPHER_AESCTR },
	{ "aes192-ctr",		16, 24, 16, 0, CIPHER_AESCTR },
	{ "aes256-ctr",		16, 32, 16, 0, CIPHER_AESCTR },
	{ "chacha20-poly1305@openssh.com",
				8, 64, 0, 16, CIPHER_CHACHAPOLY },
	{ "none",		8, 0, 0, 0, CIPHER_NONE },

	{ NULL,			0, 0, 0, 0, 0 }
};

/*--*/

/* Returns a comma-separated list of supported ciphers. */
char *
cipher_alg_list(char sep, int auth_only)
{
	char *tmp, *ret = NULL;
	size_t nlen, rlen = 0;
	const struct sshcipher *c;

	for (c = ciphers; c->name != NULL; c++) {
		if (c->type == CIPHER_NONE)
			continue;
		if (auth_only && c->auth_len == 0)
			continue;
		if (ret != NULL)
			ret[rlen++] = sep;
		nlen = strlen(c->name);
		if ((tmp = realloc(ret, rlen + nlen + 2)) == NULL) {
			free(ret);
			return NULL;
		}
		ret = tmp;
		memcpy(ret + rlen, c->name, nlen + 1);
		rlen += nlen;
	}
	return ret;
}

const char *
compression_alg_list(int compression)
{
#ifdef WITH_ZLIB
	return compression ? "zlib@openssh.com,zlib,none" :
	    "none,zlib@openssh.com,zlib";
#else
	return "none";
#endif
}

u_int
cipher_blocksize(const struct sshcipher *c)
{
	return (c->block_size);
}

u_int
cipher_keylen(const struct sshcipher *c)
{
	return (c->key_len);
}

u_int
cipher_seclen(const struct sshcipher *c)
{
	return cipher_keylen(c);
}

u_int
cipher_authlen(const struct sshcipher *c)
{
	return (c->auth_len);
}

u_int
cipher_ivlen(const struct sshcipher *c)
{
	return (c->iv_len);
}

u_int
cipher_is_cbc(const struct sshcipher *c)
{
	return c->type == CIPHER_AESCBC;
}

u_int
cipher_ctx_is_plaintext(struct sshcipher_ctx *cc)
{
	return cc->plaintext;
}

const struct sshcipher *
cipher_by_name(const char *name)
{
	const struct sshcipher *c;
	for (c = ciphers; c->name != NULL; c++)
		if (strcmp(c->name, name) == 0)
			return c;
	return NULL;
}

#define	CIPHER_SEP	","
int
ciphers_valid(const char *names)
{
	const struct sshcipher *c;
	char *cipher_list, *cp;
	char *p;

	if (names == NULL || strcmp(names, "") == 0)
		return 0;
	if ((cipher_list = cp = strdup(names)) == NULL)
		return 0;
	for ((p = strsep(&cp, CIPHER_SEP)); p && *p != '\0';
	    (p = strsep(&cp, CIPHER_SEP))) {
		c = cipher_by_name(p);
		if (c == NULL || c->type == CIPHER_NONE) {
			free(cipher_list);
			return 0;
		}
	}
	free(cipher_list);
	return 1;
}

const char *
cipher_warning_message(const struct sshcipher_ctx *cc)
{
	if (cc == NULL || cc->cipher == NULL)
		return NULL;
	/* XXX repurpose for CBC warning */
	return NULL;
}

int
cipher_init(struct sshcipher_ctx **ccp, const struct sshcipher *cipher,
    const u_char *key, u_int keylen, const u_char *iv, u_int ivlen,
    int do_encrypt)
{
	struct sshcipher_ctx *cc = NULL;
	int ret = SSH_ERR_INTERNAL_ERROR;

	*ccp = NULL;
	if ((cc = calloc(sizeof(*cc), 1)) == NULL)
		return SSH_ERR_ALLOC_FAIL;

	cc->plaintext = cipher->type == CIPHER_NONE;
	cc->encrypt = do_encrypt;

	if (keylen != cipher->key_len || ivlen != cipher_ivlen(cipher)) {
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}

	cc->cipher = cipher;
	switch (cc->cipher->type) {
	case CIPHER_NONE:
		break;
	case CIPHER_CHACHAPOLY:
		if ((cc->cp_ctx = chachapoly_new(key, keylen)) == NULL) {
			ret = SSH_ERR_INVALID_ARGUMENT;
			goto out;
		}
		break;
#ifdef WITH_BEARSSL
	case CIPHER_AESCTR:
		memcpy(cc->iv, iv, 16);
		br_aes_ct64_ctr_init(&cc->keys.ctr, key, keylen);
		break;
	case CIPHER_AESCBC:
		memcpy(cc->iv, iv, 16);
		if (do_encrypt)
			br_aes_ct64_cbcenc_init(&cc->keys.cbcenc, key, keylen);
		else
			br_aes_ct64_cbcdec_init(&cc->keys.cbcdec, key, keylen);
		break;
	case CIPHER_AESGCM:
		memcpy(cc->iv, iv, 12);
		br_aes_ct64_ctr_init(&cc->keys.ctr, key, keylen);
		br_gcm_init(&cc->gcm, &cc->keys.ctr.vtable, br_ghash_ctmul64);
		break;
#else
	case CIPHER_AESCTR:
		aesctr_keysetup(&cc->ac_ctx, key, 8 * keylen, 8 * ivlen);
		aesctr_ivsetup(&cc->ac_ctx, iv);
		break;
#endif
	default:
		ret = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	*ccp = cc;
	cc = NULL;
	ret = 0;
 out:
	freezero(cc, sizeof(*cc));
	return ret;
}

#ifdef WITH_BEARSSL
static inline void
inc_iv(u_char *iv, size_t len)
{
	while (len-- > 0 && ++iv[len] == 0)
		;
}
#endif

/*
 * cipher_crypt() operates as following:
 * Copy 'aadlen' bytes (without en/decryption) from 'src' to 'dest'.
 * These bytes are treated as additional authenticated data for
 * authenticated encryption modes.
 * En/Decrypt 'len' bytes at offset 'aadlen' from 'src' to 'dest'.
 * Use 'authlen' bytes at offset 'len'+'aadlen' as the authentication tag.
 * This tag is written on encryption and verified on decryption.
 * Both 'aadlen' and 'authlen' can be set to 0.
 */
int
cipher_crypt(struct sshcipher_ctx *cc, u_int seqnr, u_char *dest,
   const u_char *src, u_int len, u_int aadlen, u_int authlen)
{
	u_int32_t ctr;
	u_int off;

	if (authlen != cipher_authlen(cc->cipher) ||
	    len % cc->cipher->block_size != 0)
		return SSH_ERR_INVALID_ARGUMENT;

	switch (cc->cipher->type) {
	case CIPHER_NONE:
		memcpy(dest, src, aadlen + len);
		break;
	case CIPHER_CHACHAPOLY:
		return chachapoly_crypt(cc->cp_ctx, seqnr, dest, src,
		    len, aadlen, authlen, cc->encrypt);
#ifdef WITH_BEARSSL
	case CIPHER_AESCTR:
		memcpy(dest, src, aadlen + len);
		ctr = PEEK_U32(cc->iv + 12);
		off = -ctr < len / 16 ? -ctr * 16 : len;
		ctr = br_aes_ct64_ctr_run(&cc->keys.ctr, cc->iv, ctr,
		    dest + aadlen, off);
		/* If the counter rolled over (possible since the
		 * initial value comes from a hash), increment the
		 * IV, then process the rest of the message. */
		if (ctr == 0) {
			inc_iv(cc->iv, 12);
			ctr = br_aes_ct64_ctr_run(&cc->keys.ctr, cc->iv, ctr,
			   dest + aadlen + off, len - off);
		}
		POKE_U32(cc->iv + 12, ctr);
		break;
	case CIPHER_AESCBC:
		memcpy(dest, src, aadlen + len);
		if (cc->encrypt) {
			br_aes_ct64_cbcenc_run(&cc->keys.cbcenc, cc->iv,
			    dest + aadlen, len);
		} else {
			br_aes_ct64_cbcdec_run(&cc->keys.cbcdec, cc->iv,
			    dest + aadlen, len);
		}
		break;
	case CIPHER_AESGCM:
		memcpy(dest, src, aadlen + len);
		br_gcm_reset(&cc->gcm, cc->iv, 12);
		inc_iv(cc->iv + 4, 8);
		br_gcm_aad_inject(&cc->gcm, dest, aadlen);
		br_gcm_flip(&cc->gcm);
		br_gcm_run(&cc->gcm, cc->encrypt, dest + aadlen, len);
		if (cc->encrypt) {
			br_gcm_get_tag(&cc->gcm, dest + aadlen + len);
		} else if (br_gcm_check_tag(&cc->gcm,
		    src + aadlen + len) != 1) {
			return SSH_ERR_MAC_INVALID;
		}
		break;
#else
	case CIPHER_AESCTR:
		if (aadlen)
			memcpy(dest, src, aadlen);
		aesctr_encrypt_bytes(&cc->ac_ctx, src + aadlen,
		    dest + aadlen, len);
		break;
#endif
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	return 0;
}

/* Extract the packet length, including any decryption necessary beforehand */
int
cipher_get_length(struct sshcipher_ctx *cc, u_int *plenp, u_int seqnr,
    const u_char *cp, u_int len)
{
	if (cc->cipher->type == CIPHER_CHACHAPOLY)
		return chachapoly_get_length(cc->cp_ctx, plenp, seqnr,
		    cp, len);
	if (len < 4)
		return SSH_ERR_MESSAGE_INCOMPLETE;
	*plenp = PEEK_U32(cp);
	return 0;
}

void
cipher_free(struct sshcipher_ctx *cc)
{
	if (cc == NULL)
		return;
	if (cc->cipher->type == CIPHER_CHACHAPOLY) {
		chachapoly_free(cc->cp_ctx);
		cc->cp_ctx = NULL;
	}
	freezero(cc, sizeof(*cc));
}

int
cipher_get_keyiv(struct sshcipher_ctx *cc, u_char *iv, size_t len)
{

	if (len != cipher_ivlen(cc->cipher))
		return SSH_ERR_INVALID_ARGUMENT;

	switch (cc->cipher->type) {
#ifdef WITH_BEARSSL
	case CIPHER_AESCTR:
	case CIPHER_AESCBC:
	case CIPHER_AESGCM:
		memcpy(iv, cc->iv, len);
		break;
#else
	case CIPHER_AESCTR:
		memcpy(iv, cc->ac_ctx.ctr, len);
		break;
#endif
	case CIPHER_CHACHAPOLY:
		break;
	default:
		return SSH_ERR_INVALID_ARGUMENT;
	}
	return 0;
}
