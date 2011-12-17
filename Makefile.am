# Copyright (c) 2002, 2004 Andrew J. Korty
# All rights reserved.
# 
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 
# THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
# FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
# OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.
# 
# $Id: Makefile.am,v 1.18 2004/02/20 14:57:23 akorty Exp $

lib_LTLIBRARIES			= pam_ssh.la
pam_ssh_la_LDFLAGS		= -avoid-version -module
pam_ssh_la_LIBADD		= @LTLIBOBJS@
pam_ssh_la_SOURCES		= atomicio.c atomicio.h authfd.c authfd.h   \
				  authfile.c authfile.h bufaux.c bufaux.h   \
				  buffer.c buffer.h cipher.c cipher.h	    \
				  cipher-3des1.c cipher-bf1.c cipher-ctr.c  \
				  getput.h kex.h key.c key.h log.c log.h    \
				  pam_ssh.c rijndael.c rijndael.h xmalloc.c \
				  xmalloc.h
libdir				= @PAMDIR@
man_MANS			= pam_ssh.8
AM_CFLAGS			= -Wall
AUTOMAKE_OPTIONS		= dist-bzip2
EXTRA_pam_ssh_la_SOURCES	= openpam_cred.h pam_opttab.h pam_option.h \
				  pam_get_pass.h strlcpy.h strnvis.h
EXTRA_DIST			= $(man_MANS) bootstrap.sh pam_ssh.spec \
				  pam_test.c
LIBTOOL_DEPS			= @LIBTOOL_DEPS@

libtool: $(LIBTOOL_DEPS)
	$(SHELL) ./config.status --recheck
