/* $OpenBSD: hash.c,v 1.6 2019/11/29 00:11:21 djm Exp $ */
/*
 * Public domain. Author: Christian Weisgerber <naddy@openbsd.org>
 * API compatible reimplementation of function from nacl
 */

#include "includes.h"

#include "crypto_api.h"

#include <stdarg.h>

#ifdef WITH_BEARSSL
#include <bearssl.h>

int
crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    unsigned long long inlen)
{

	br_sha512_context ctx;

	br_sha512_init(&ctx);
	br_sha512_update(&ctx, in, inlen);
	br_sha512_out(&ctx, out);
	return 0;
}

#else
# ifdef HAVE_SHA2_H
#  include <sha2.h>
# endif

int
crypto_hash_sha512(unsigned char *out, const unsigned char *in,
    unsigned long long inlen)
{

	SHA2_CTX ctx;

	SHA512Init(&ctx);
	SHA512Update(&ctx, in, inlen);
	SHA512Final(out, &ctx);
	return 0;
}
#endif /* WITH_BEARSSL */
