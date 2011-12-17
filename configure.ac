dnl Copyright (c) 2002, 2004, 2007 Andrew J. Korty
dnl All rights reserved.
dnl 
dnl Redistribution and use in source and binary forms, with or without
dnl modification, are permitted provided that the following conditions
dnl are met:
dnl 1. Redistributions of source code must retain the above copyright
dnl    notice, this list of conditions and the following disclaimer.
dnl 2. Redistributions in binary form must reproduce the above copyright
dnl    notice, this list of conditions and the following disclaimer in the
dnl    documentation and/or other materials provided with the distribution.
dnl 
dnl THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
dnl ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
dnl IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
dnl ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
dnl FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
dnl DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
dnl OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
dnl HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
dnl LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
dnl OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
dnl SUCH DAMAGE.
dnl
dnl $Id: configure.ac,v 1.10 2007/02/06 18:11:08 akorty Exp $

dnl Process this file with autoconf to produce a configure script.

AC_INIT([pam_ssh],[1.92],[ajk@ajk.name])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_SRCDIR([pam_ssh.c])
AC_CANONICAL_TARGET([])
AM_DISABLE_STATIC
AM_INIT_AUTOMAKE(pam_ssh, 1.92)
AM_PROG_LIBTOOL
AC_SUBST(LIBTOOL_DEPS)

dnl Checks for programs.

AC_PATH_PROG(PATH_SSH_AGENT, ssh-agent, no)
if test x"$PATH_SSH_AGENT" = xno; then
  AC_MSG_ERROR([Could not find ssh-agent, please install or check config.log])
fi
AC_DEFINE_UNQUOTED([PATH_SSH_AGENT], ["$PATH_SSH_AGENT"], [Path to ssh-agent])

dnl Checks for libraries.

# The big search for OpenSSL (stolen from OpenSSH 3.1's configure.ac)
AC_ARG_WITH(ssl-dir,
	[  --with-ssl-dir=PATH     Specify path to OpenSSL installation ],
	[
		if test "x$withval" != "xno" ; then
			tryssldir=$withval
		fi
	]
)

saved_LIBS="$LIBS"
saved_LDFLAGS="$LDFLAGS"
saved_CPPFLAGS="$CPPFLAGS"
if test "x$prefix" != "xNONE" ; then
	tryssldir="$tryssldir $prefix"
fi
AC_CACHE_CHECK([for OpenSSL directory], ac_cv_openssldir, [
	for ssldir in $tryssldir "" /usr/local/openssl /usr/lib/openssl /usr/local/ssl /usr/lib/ssl /usr/local /usr/pkg /opt /opt/openssl ; do
		CPPFLAGS="$saved_CPPFLAGS"
		LDFLAGS="$saved_LDFLAGS"
		LIBS="$saved_LIBS -lcrypto"
		
		# Skip directories if they don't exist
		if test ! -z "$ssldir" -a ! -d "$ssldir" ; then
			continue;
		fi
		if test ! -z "$ssldir" -a "x$ssldir" != "x/usr"; then
			# Try to use $ssldir/lib if it exists, otherwise 
			# $ssldir
			if test -d "$ssldir/lib" ; then
				LDFLAGS="-L$ssldir/lib $saved_LDFLAGS"
				if test ! -z "$need_dash_r" ; then
					LDFLAGS="-R$ssldir/lib $LDFLAGS"
				fi
			else
				LDFLAGS="-L$ssldir $saved_LDFLAGS"
				if test ! -z "$need_dash_r" ; then
					LDFLAGS="-R$ssldir $LDFLAGS"
				fi
			fi
			# Try to use $ssldir/include if it exists, otherwise 
			# $ssldir
			if test -d "$ssldir/include" ; then
				CPPFLAGS="-I$ssldir/include $saved_CPPFLAGS"
			else
				CPPFLAGS="-I$ssldir $saved_CPPFLAGS"
			fi
		fi

		# Basic test to check for compatible version and correct linking
		# *does not* test for RSA - that comes later.
		AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <string.h>
#include <openssl/rand.h>
int main(void) 
{
	char a[2048];
	memset(a, 0, sizeof(a));
	RAND_add(a, sizeof(a), sizeof(a));
	return(RAND_status() <= 0);
}
			]])],[
				found_crypto=1
				break;
			],[
		],[])

		if test ! -z "$found_crypto" ; then
			break;
		fi
	done

	if test -z "$found_crypto" ; then
		AC_MSG_ERROR([Could not find working OpenSSL library, please install or check config.log])	
	fi
	if test -z "$ssldir" ; then
		ssldir="(system)"
	fi

	ac_cv_openssldir=$ssldir
])

if (test ! -z "$ac_cv_openssldir" && test "x$ac_cv_openssldir" != "x(system)") ; then
	AC_DEFINE(HAVE_OPENSSL, [], [Define if we have OpenSSL])
	dnl Need to recover ssldir - test above runs in subshell
	ssldir=$ac_cv_openssldir
	if test ! -z "$ssldir" -a "x$ssldir" != "x/usr"; then
		# Try to use $ssldir/lib if it exists, otherwise 
		# $ssldir
		if test -d "$ssldir/lib" ; then
			LDFLAGS="-L$ssldir/lib $saved_LDFLAGS"
			if test ! -z "$need_dash_r" ; then
				LDFLAGS="-R$ssldir/lib $LDFLAGS"
			fi
		else
			LDFLAGS="-L$ssldir $saved_LDFLAGS"
			if test ! -z "$need_dash_r" ; then
				LDFLAGS="-R$ssldir $LDFLAGS"
			fi
		fi
		# Try to use $ssldir/include if it exists, otherwise 
		# $ssldir
		if test -d "$ssldir/include" ; then
			CPPFLAGS="-I$ssldir/include $saved_CPPFLAGS"
		else
			CPPFLAGS="-I$ssldir $saved_CPPFLAGS"
		fi
	fi
fi
LIBS="$saved_LIBS -lcrypto"

# Now test RSA support
saved_LIBS="$LIBS"
AC_MSG_CHECKING([for RSA support])
for WANTS_RSAREF in "" 1 ; do
	if test -z "$WANTS_RSAREF" ; then
		LIBS="$saved_LIBS"
	else
		LIBS="$saved_LIBS -lRSAglue -lrsaref"
	fi
	AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <string.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
int main(void) 
{
	int num; RSA *key; static unsigned char p_in[] = "blahblah";
	unsigned char c[256], p[256];
	memset(c, 0, sizeof(c)); RAND_add(c, sizeof(c), sizeof(c));
	if ((key=RSA_generate_key(512, 3, NULL, NULL))==NULL) return(1);
	num = RSA_public_encrypt(sizeof(p_in) - 1, p_in, c, key, RSA_PKCS1_PADDING);
	return(-1 == RSA_private_decrypt(num, c, p, key, RSA_PKCS1_PADDING));
}
	]])],[
		rsa_works=1
		break;
	],[],[])
done
LIBS="$saved_LIBS"

if test ! -z "$no_rsa" ; then
	AC_MSG_RESULT(disabled)
	RSA_MSG="disabled"
else
	if test -z "$rsa_works" ; then
		AC_MSG_WARN([*** No RSA support found *** ])
		RSA_MSG="no"
	else
		if test -z "$WANTS_RSAREF" ; then
			AC_MSG_RESULT(yes)
			RSA_MSG="yes"
		else
			RSA_MSG="yes (using RSAref)"
			AC_MSG_RESULT(using RSAref)
			LIBS="$LIBS -lcrypto -lRSAglue -lrsaref"
		fi
	fi
fi

# Sanity check OpenSSL headers
AC_MSG_CHECKING([whether OpenSSL's headers match the library])
AC_RUN_IFELSE([AC_LANG_SOURCE([[
#include <string.h>
#include <openssl/opensslv.h>
int main(void) { return(SSLeay() == OPENSSL_VERSION_NUMBER ? 0 : 1); }
	]])],[
		AC_MSG_RESULT(yes)
	],[
		AC_MSG_RESULT(no)
		AC_MSG_ERROR(Your OpenSSL headers do not match your library)
	
],[])

dnl Checks for header files.

AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS(stdlib.h string.h)

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_UID_T

dnl Checks for library functions.
AC_CHECK_FUNCS(memmove memset)
AC_REPLACE_FUNCS(strlcpy strnvis)
AC_CHECK_PAM

AC_CONFIG_FILES([Makefile])
AC_SUBST(LTLIBOBJS)
AC_OUTPUT
