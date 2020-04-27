/* 	$OpenBSD: common.h,v 1.2 2018/09/13 09:03:20 djm Exp $ */
/*
 * Helpers for key API tests
 *
 * Placed in the public domain
 */

/* Load a binary file into a buffer */
struct sshbuf *load_file(const char *name);

/* Load a text file into a buffer */
struct sshbuf *load_text_file(const char *name);

struct bignum {
	u_char *num;
	size_t len;
};

/* Load a bignum from a file */
void load_bignum(const char *name, struct bignum *num);
