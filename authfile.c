/*
 * Author: Tatu Ylonen <ylo@cs.hut.fi>
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *                    All rights reserved
 * This file contains functions for reading and writing identity files, and
 * for reading the passphrase from the user.
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * Copyright (c) 2000 Markus Friedl.  All rights reserved.
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

#include <sys/param.h>
#include <sys/stat.h>

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <config.h>
#include "cipher.h"
#include "xmalloc.h"
#include "buffer.h"
#include "bufaux.h"
#include "key.h"
#include "log.h"

/* Version identification string for SSH v1 identity files. */
static const char authfile_id_string[] =
    "SSH PRIVATE KEY FILE FORMAT 1.1\n";


/*
 * Loads the public part of the ssh v1 key file.  Returns NULL if an error was
 * encountered (the file does not exist or is not readable), and the key
 * otherwise.
 */

static Key *
key_load_public_rsa1(int fd, const char *filename, char **commentp)
{
	Buffer buffer;
	Key *pub;
	struct stat st;
	char *cp;
	int i;
	off_t len;

	if (fstat(fd, &st) < 0) {
		error("fstat for key file %.200s failed: %.100s",
		    filename, strerror(errno));
		return NULL;
	}
	len = st.st_size;

	buffer_init(&buffer);
	cp = buffer_append_space(&buffer, len);

	if (read(fd, cp, (size_t) len) != (size_t) len) {
		debug("Read from key file %.200s failed: %.100s", filename,
		    strerror(errno));
		buffer_free(&buffer);
		return NULL;
	}

	/* Check that it is at least big enough to contain the ID string. */
	if (len < sizeof(authfile_id_string)) {
		debug3("Not a RSA1 key file %.200s.", filename);
		buffer_free(&buffer);
		return NULL;
	}
	/*
	 * Make sure it begins with the id string.  Consume the id string
	 * from the buffer.
	 */
	for (i = 0; i < sizeof(authfile_id_string); i++)
		if (buffer_get_char(&buffer) != authfile_id_string[i]) {
			debug3("Not a RSA1 key file %.200s.", filename);
			buffer_free(&buffer);
			return NULL;
		}
	/* Skip cipher type and reserved data. */
	(void) buffer_get_char(&buffer);	/* cipher type */
	(void) buffer_get_int(&buffer);		/* reserved */

	/* Read the public key from the buffer. */
	(void) buffer_get_int(&buffer);
	pub = key_new(KEY_RSA1);
	buffer_get_bignum(&buffer, pub->rsa->n);
	buffer_get_bignum(&buffer, pub->rsa->e);
	if (commentp)
		*commentp = buffer_get_string(&buffer, NULL);
	/* The encrypted private part is not parsed by this function. */

	buffer_free(&buffer);
	return pub;
}

/* load public key from private-key file, works only for SSH v1 */
Key *
key_load_public_type(int type, const char *filename, char **commentp)
{
	Key *pub;
	int fd;

	if (type == KEY_RSA1) {
		fd = open(filename, O_RDONLY);
		if (fd < 0)
			return NULL;
		pub = key_load_public_rsa1(fd, filename, commentp);
		close(fd);
		return pub;
	}
	return NULL;
}

/* calculate p-1 and q-1 */
void
rsa_generate_additional_parameters(RSA *rsa)
{
	BIGNUM *aux;
	BN_CTX *ctx;

	if ((aux = BN_new()) == NULL)
		fatal("rsa_generate_additional_parameters: BN_new failed");
	if ((ctx = BN_CTX_new()) == NULL)
		fatal("rsa_generate_additional_parameters: BN_CTX_new failed");

	BN_sub(aux, rsa->q, BN_value_one());
	BN_mod(rsa->dmq1, rsa->d, aux, ctx);

	BN_sub(aux, rsa->p, BN_value_one());
	BN_mod(rsa->dmp1, rsa->d, aux, ctx);

	BN_clear_free(aux);
	BN_CTX_free(ctx);
}

/*
 * Loads the private key from the file.  Returns 0 if an error is encountered
 * (file does not exist or is not readable, or passphrase is bad). This
 * initializes the private key.
 * Assumes we are called under uid of the owner of the file.
 */

static Key *
key_load_private_rsa1(int fd, const char *filename, const char *passphrase,
    char **commentp)
{
	int i, check1, check2, cipher_type;
	off_t len;
	Buffer buffer, decrypted;
	u_char *cp;
	CipherContext ciphercontext;
	Cipher *cipher;
	Key *prv = NULL;
	struct stat st;

	if (fstat(fd, &st) < 0) {
		error("fstat for key file %.200s failed: %.100s",
		    filename, strerror(errno));
		close(fd);
		return NULL;
	}
	len = st.st_size;

	buffer_init(&buffer);
	cp = buffer_append_space(&buffer, len);

	if (read(fd, cp, (size_t) len) != (size_t) len) {
		debug("Read from key file %.200s failed: %.100s", filename,
		    strerror(errno));
		buffer_free(&buffer);
		close(fd);
		return NULL;
	}

	/* Check that it is at least big enough to contain the ID string. */
	if (len < sizeof(authfile_id_string)) {
		debug3("Not a RSA1 key file %.200s.", filename);
		buffer_free(&buffer);
		close(fd);
		return NULL;
	}
	/*
	 * Make sure it begins with the id string.  Consume the id string
	 * from the buffer.
	 */
	for (i = 0; i < sizeof(authfile_id_string); i++)
		if (buffer_get_char(&buffer) != authfile_id_string[i]) {
			debug3("Not a RSA1 key file %.200s.", filename);
			buffer_free(&buffer);
			close(fd);
			return NULL;
		}

	/* Read cipher type. */
	cipher_type = buffer_get_char(&buffer);
	(void) buffer_get_int(&buffer);	/* Reserved data. */

	/* Read the public key from the buffer. */
	(void) buffer_get_int(&buffer);
	prv = key_new_private(KEY_RSA1);

	buffer_get_bignum(&buffer, prv->rsa->n);
	buffer_get_bignum(&buffer, prv->rsa->e);
	if (commentp)
		*commentp = buffer_get_string(&buffer, NULL);
	else
		xfree(buffer_get_string(&buffer, NULL));

	/* Check that it is a supported cipher. */
	cipher = cipher_by_number(cipher_type);
	if (cipher == NULL) {
		debug("Unsupported cipher %d used in key file %.200s.",
		    cipher_type, filename);
		buffer_free(&buffer);
		goto fail;
	}
	/* Initialize space for decrypted data. */
	buffer_init(&decrypted);
	cp = buffer_append_space(&decrypted, buffer_len(&buffer));

	/* Rest of the buffer is encrypted.  Decrypt it using the passphrase. */
	cipher_set_key_string(&ciphercontext, cipher, passphrase,
	    CIPHER_DECRYPT);
	cipher_crypt(&ciphercontext, cp,
	    buffer_ptr(&buffer), buffer_len(&buffer));
	cipher_cleanup(&ciphercontext);
	memset(&ciphercontext, 0, sizeof(ciphercontext));
	buffer_free(&buffer);

	check1 = buffer_get_char(&decrypted);
	check2 = buffer_get_char(&decrypted);
	if (check1 != buffer_get_char(&decrypted) ||
	    check2 != buffer_get_char(&decrypted)) {
		if (strcmp(passphrase, "") != 0)
			debug("Bad passphrase supplied for key file %.200s.",
			    filename);
		/* Bad passphrase. */
		buffer_free(&decrypted);
		goto fail;
	}
	/* Read the rest of the private key. */
	buffer_get_bignum(&decrypted, prv->rsa->d);
	buffer_get_bignum(&decrypted, prv->rsa->iqmp);		/* u */
	/* in SSL and SSH v1 p and q are exchanged */
	buffer_get_bignum(&decrypted, prv->rsa->q);		/* p */
	buffer_get_bignum(&decrypted, prv->rsa->p);		/* q */

	/* calculate p-1 and q-1 */
	rsa_generate_additional_parameters(prv->rsa);

	buffer_free(&decrypted);

	/* enable blinding */
	if (RSA_blinding_on(prv->rsa, NULL) != 1) {
		error("key_load_private_rsa1: RSA_blinding_on failed");
		goto fail;
	}
	close(fd);
	return prv;

fail:
	if (commentp)
		xfree(*commentp);
	close(fd);
	key_free(prv);
	return NULL;
}

Key *
key_load_private_pem(int fd, int type, const char *passphrase,
    char **commentp)
{
	FILE *fp;
	EVP_PKEY *pk = NULL;
	Key *prv = NULL;
	char *name = "<no key>";

	fp = fdopen(fd, "r");
	if (fp == NULL) {
		error("fdopen failed: %s", strerror(errno));
		close(fd);
		return NULL;
	}
	pk = PEM_read_PrivateKey(fp, NULL, NULL, (char *)passphrase);
	if (pk == NULL) {
		debug("PEM_read_PrivateKey failed");
		(void)ERR_get_error();
	} else if (pk->type == EVP_PKEY_RSA &&
	    (type == KEY_UNSPEC||type==KEY_RSA)) {
		prv = key_new(KEY_UNSPEC);
		prv->rsa = EVP_PKEY_get1_RSA(pk);
		prv->type = KEY_RSA;
		name = "rsa w/o comment";
#ifdef DEBUG_PK
		RSA_print_fp(stderr, prv->rsa, 8);
#endif
		if (RSA_blinding_on(prv->rsa, NULL) != 1) {
			error("key_load_private_pem: RSA_blinding_on failed");
			key_free(prv);
			prv = NULL;
		}
	} else if (pk->type == EVP_PKEY_DSA &&
	    (type == KEY_UNSPEC||type==KEY_DSA)) {
		prv = key_new(KEY_UNSPEC);
		prv->dsa = EVP_PKEY_get1_DSA(pk);
		prv->type = KEY_DSA;
		name = "dsa w/o comment";
#ifdef DEBUG_PK
		DSA_print_fp(stderr, prv->dsa, 8);
#endif
	} else {
		error("PEM_read_PrivateKey: mismatch or "
		    "unknown EVP_PKEY save_type %d", pk->save_type);
	}
	fclose(fp);
	if (pk != NULL)
		EVP_PKEY_free(pk);
	if (prv != NULL && commentp)
		*commentp = xstrdup(name);
	debug("read PEM private key done: type %s",
	    prv ? key_type(prv) : "<unknown>");
	return prv;
}

static int
key_perm_ok(int fd, const char *filename)
{
	struct stat st;

	if (fstat(fd, &st) < 0)
		return 0;
	/*
	 * if a key owned by the user is accessed, then we check the
	 * permissions of the file. if the key owned by a different user,
	 * then we don't care.
	 */
#ifdef HAVE_CYGWIN
	if (check_ntsec(filename))
#endif
	if ((st.st_uid == getuid()) && (st.st_mode & 077) != 0) {
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("@         WARNING: UNPROTECTED PRIVATE KEY FILE!          @");
		error("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@");
		error("Permissions 0%3.3o for '%s' are too open.",
		    (u_int)st.st_mode & 0777, filename);
		error("It is recommended that your private key files are NOT accessible by others.");
		error("This private key will be ignored.");
		return 0;
	}
	return 1;
}

Key *
key_load_private_type(int type, const char *filename, const char *passphrase,
    char **commentp)
{
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return NULL;
	if (!key_perm_ok(fd, filename)) {
		error("bad permissions: ignore key: %s", filename);
		close(fd);
		return NULL;
	}
	switch (type) {
	case KEY_RSA1:
		return key_load_private_rsa1(fd, filename, passphrase,
		    commentp);
		/* closes fd */
		break;
	case KEY_DSA:
	case KEY_RSA:
	case KEY_UNSPEC:
		return key_load_private_pem(fd, type, passphrase, commentp);
		/* closes fd */
		break;
	default:
		close(fd);
		break;
	}
	return NULL;
}

Key *
key_load_private(const char *filename, const char *passphrase,
    char **commentp)
{
	Key *pub, *prv;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0)
		return NULL;
	if (!key_perm_ok(fd, filename)) {
		error("bad permissions: ignore key: %s", filename);
		close(fd);
		return NULL;
	}
	pub = key_load_public_rsa1(fd, filename, commentp);
	lseek(fd, (off_t) 0, SEEK_SET);		/* rewind */
	if (pub == NULL) {
		/* closes fd */
		prv = key_load_private_pem(fd, KEY_UNSPEC, passphrase, NULL);
		/* use the filename as a comment for PEM */
		if (commentp && prv)
			*commentp = xstrdup(filename);
	} else {
		/* it's a SSH v1 key if the public key part is readable */
		key_free(pub);
		/* closes fd */
		prv = key_load_private_rsa1(fd, filename, passphrase, NULL);
	}
	return prv;
}
