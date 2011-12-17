/*
 * read_bignum():
 * Copyright (c) 1995 Tatu Ylonen <ylo@cs.hut.fi>, Espoo, Finland
 *
 * As far as I am concerned, the code I have written for this software
 * can be used freely for any purpose.  Any derived versions of this
 * software must be clearly marked as such, and if the derived work is
 * incompatible with the protocol description in the RFC file, it must be
 * called by a name other than "ssh" or "Secure Shell".
 *
 *
 * Copyright (c) 2000, 2001 Markus Friedl.  All rights reserved.
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

#include <sys/types.h>

#include <openssl/evp.h>

#include <string.h>

#include <config.h>
#include "xmalloc.h"
#include "key.h"
#include "buffer.h"
#include "bufaux.h"
#include "log.h"

Key *
key_new(int type)
{
	Key *k;
	RSA *rsa;
	DSA *dsa;
	k = xmalloc(sizeof(*k));
	k->type = type;
	k->flags = 0;
	k->dsa = NULL;
	k->rsa = NULL;
	switch (k->type) {
	case KEY_RSA1:
	case KEY_RSA:
		if ((rsa = RSA_new()) == NULL)
			fatal("key_new: RSA_new failed");
		if ((rsa->n = BN_new()) == NULL)
			fatal("key_new: BN_new failed");
		if ((rsa->e = BN_new()) == NULL)
			fatal("key_new: BN_new failed");
		k->rsa = rsa;
		break;
	case KEY_DSA:
		if ((dsa = DSA_new()) == NULL)
			fatal("key_new: DSA_new failed");
		if ((dsa->p = BN_new()) == NULL)
			fatal("key_new: BN_new failed");
		if ((dsa->q = BN_new()) == NULL)
			fatal("key_new: BN_new failed");
		if ((dsa->g = BN_new()) == NULL)
			fatal("key_new: BN_new failed");
		if ((dsa->pub_key = BN_new()) == NULL)
			fatal("key_new: BN_new failed");
		k->dsa = dsa;
		break;
	case KEY_UNSPEC:
		break;
	default:
		fatal("key_new: bad key type %d", k->type);
		break;
	}
	return k;
}

Key *
key_new_private(int type)
{
	Key *k = key_new(type);
	switch (k->type) {
	case KEY_RSA1:
	case KEY_RSA:
		if ((k->rsa->d = BN_new()) == NULL)
			fatal("key_new_private: BN_new failed");
		if ((k->rsa->iqmp = BN_new()) == NULL)
			fatal("key_new_private: BN_new failed");
		if ((k->rsa->q = BN_new()) == NULL)
			fatal("key_new_private: BN_new failed");
		if ((k->rsa->p = BN_new()) == NULL)
			fatal("key_new_private: BN_new failed");
		if ((k->rsa->dmq1 = BN_new()) == NULL)
			fatal("key_new_private: BN_new failed");
		if ((k->rsa->dmp1 = BN_new()) == NULL)
			fatal("key_new_private: BN_new failed");
		break;
	case KEY_DSA:
		if ((k->dsa->priv_key = BN_new()) == NULL)
			fatal("key_new_private: BN_new failed");
		break;
	case KEY_UNSPEC:
		break;
	default:
		break;
	}
	return k;
}

void
key_free(Key *k)
{
	switch (k->type) {
	case KEY_RSA1:
	case KEY_RSA:
		if (k->rsa != NULL)
			RSA_free(k->rsa);
		k->rsa = NULL;
		break;
	case KEY_DSA:
		if (k->dsa != NULL)
			DSA_free(k->dsa);
		k->dsa = NULL;
		break;
	case KEY_UNSPEC:
		break;
	default:
		fatal("key_free: bad key type %d", k->type);
		break;
	}
	xfree(k);
}
int
key_equal(Key *a, Key *b)
{
	if (a == NULL || b == NULL || a->type != b->type)
		return 0;
	switch (a->type) {
	case KEY_RSA1:
	case KEY_RSA:
		return a->rsa != NULL && b->rsa != NULL &&
		    BN_cmp(a->rsa->e, b->rsa->e) == 0 &&
		    BN_cmp(a->rsa->n, b->rsa->n) == 0;
		break;
	case KEY_DSA:
		return a->dsa != NULL && b->dsa != NULL &&
		    BN_cmp(a->dsa->p, b->dsa->p) == 0 &&
		    BN_cmp(a->dsa->q, b->dsa->q) == 0 &&
		    BN_cmp(a->dsa->g, b->dsa->g) == 0 &&
		    BN_cmp(a->dsa->pub_key, b->dsa->pub_key) == 0;
		break;
	default:
		fatal("key_equal: bad key type %d", a->type);
		break;
	}
	return 0;
}

char *
key_type(Key *k)
{
	switch (k->type) {
	case KEY_RSA1:
		return "RSA1";
		break;
	case KEY_RSA:
		return "RSA";
		break;
	case KEY_DSA:
		return "DSA";
		break;
	}
	return "unknown";
}

char *
key_ssh_name(Key *k)
{
	switch (k->type) {
	case KEY_RSA:
		return "ssh-rsa";
		break;
	case KEY_DSA:
		return "ssh-dss";
		break;
	}
	return "ssh-unknown";
}

int
key_type_from_name(char *name)
{
	if (strcmp(name, "rsa1") == 0) {
		return KEY_RSA1;
	} else if (strcmp(name, "rsa") == 0) {
		return KEY_RSA;
	} else if (strcmp(name, "dsa") == 0) {
		return KEY_DSA;
	} else if (strcmp(name, "ssh-rsa") == 0) {
		return KEY_RSA;
	} else if (strcmp(name, "ssh-dss") == 0) {
		return KEY_DSA;
	}
	debug2("key_type_from_name: unknown key type '%s'", name);
	return KEY_UNSPEC;
}
