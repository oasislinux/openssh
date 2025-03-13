/* 	$OpenBSD: common.c,v 1.6 2024/08/15 00:52:23 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

#include "includes.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef WITH_BEARSSL
#include <bearssl.h>
#endif /* WITH_BEARSSL */

#include "../test_helper/test_helper.h"

#include "ssherr.h"
#include "authfile.h"
#include "sshkey.h"
#include "sshbuf.h"

#include "common.h"

struct sshbuf *
load_file(const char *name)
{
	struct sshbuf *ret = NULL;

	ASSERT_INT_EQ(sshbuf_load_file(test_data_file(name), &ret), 0);
	ASSERT_PTR_NE(ret, NULL);
	return ret;
}

struct sshbuf *
load_text_file(const char *name)
{
	struct sshbuf *ret = load_file(name);
	const u_char *p;

	/* Trim whitespace at EOL */
	for (p = sshbuf_ptr(ret); sshbuf_len(ret) > 0;) {
		if (p[sshbuf_len(ret) - 1] == '\r' ||
		    p[sshbuf_len(ret) - 1] == '\t' ||
		    p[sshbuf_len(ret) - 1] == ' ' ||
		    p[sshbuf_len(ret) - 1] == '\n')
			ASSERT_INT_EQ(sshbuf_consume_end(ret, 1), 0);
		else
			break;
	}
	/* \0 terminate */
	ASSERT_INT_EQ(sshbuf_put_u8(ret, 0), 0);
	return ret;
}

#ifdef WITH_BEARSSL
static u_int
hexval(int c)
{
	ASSERT_INT_EQ(('0' <= c && c <= '9') || ('a' <= c && c <= 'f') ||
	    ('A' <= c && c <= 'F'), 1);
	if ('0' <= c && c <= '9')
		return c - '0';
	if ('a' <= c && c <= 'f')
		return c - 'a' + 10;
	return c - 'A' + 10;
}

void
load_bignum(const char *name, struct bignum *bn)
{
	struct sshbuf *buf;
	const u_char *ptr;
	size_t len;
	size_t i;

	buf = load_text_file(name);
	ptr = sshbuf_ptr(buf);
	len = sshbuf_len(buf);
	ASSERT_INT_EQ(len % 2, 1);
	while (len >= 2 && ptr[0] == '0' && ptr[1] == '0') {
		ptr += 2;
		len -= 2;
	}
	bn->len = len / 2;
	ASSERT_PTR_NE((bn->num = malloc(bn->len)), NULL);
	for (i = 0; i < bn->len; ++i)
		bn->num[i] = hexval(ptr[i * 2]) << 4 | hexval(ptr[i * 2 + 1]);
	sshbuf_free(buf);
}
#endif /* WITH_BEARSSL */
