dnl Copyright (c) 2002, 2004 Andrew J. Korty
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
dnl $Id: acinclude.m4,v 1.12 2004/02/20 14:58:07 akorty Exp $
dnl
dnl --with-pam-libdir (based on macro from pam_krb5 1.0.3)
dnl
AC_DEFUN(AC_CHECK_PAM, 
[
    AC_ARG_WITH(pam-dir,
    AC_HELP_STRING(--with-pam-dir=dir,
        [Where to put pam module [[LIBDIR/security]]]),
    [
        case "$withval" in
        yes|no)
            #
            # Just in case anybody calls it without argument
            #
            AC_MSG_ERROR([--with-pam-dir requires a valid argument])
            ;;
        *)
            PAMDIR="$withval"
            AC_MSG_CHECKING(installing PAM modules in)
            AC_MSG_RESULT(${PAMDIR})
            ;;
        esac
    ],
    [ 
        for dir in /lib/security /usr/lib/security /usr/lib/pam /usr/lib \
               ${prefix}/lib/security ${prefix}/lib/pam ${prefix}/lib
        do
            AC_MSG_CHECKING(if we can install PAM modules in ${dir})
            if test -d ${dir}; then
                AC_MSG_RESULT(yes)
                PAMDIR=${dir}
                break;
	    else 
                AC_MSG_RESULT(no)
            fi
        done
        if test -z "${PAMDIR}"; then
            AC_MSG_ERROR(couldn't figure it out: please use --with-pam-libdir)
        fi
    ])

    dnl Search for PAM headers

    saved_CPPFLAGS="$CPPFLAGS"
    AC_CACHE_CHECK([for PAM header subdirectory], ac_cv_pamincludedir, [
        for dir in ${includedir}/security ${includedir}/pam /usr/include/security /usr/include/pam; do
    	    CPPFLAGS="$saved_CPPFLAGS"
    	    if test -f "$dir/pam_modules.h"; then
    	        CPPFLAGS="-I$dir $saved_CPPFLAGS"
	        ac_cv_pamincludedir=$dir
	        break
    	    fi
	done
    ])

    dnl Abort if we have no PAM

    AC_CHECK_LIB(pam, main, :,
        AC_MSG_ERROR(you must have PAM to use this product))

    dnl Check for pam_mod_misc.h extensions to PAM.

    AC_CHECK_HEADERS([pam_mod_misc.h],,, [#include <pam_modules.h>])

    dnl Some systems keep these extensions in a separate library

    AC_SEARCH_LIBS([pam_get_data], [pam pam_misc])
    AC_SEARCH_LIBS([pam_get_item], [pam pam_misc])
    AC_SEARCH_LIBS([pam_get_pass], [pam pam_misc],
        [AC_DEFINE([HAVE_PAM_GET_PASS], 1,
	    [Define if we have pam_get_pass()])],
	[AC_LIBOBJ(pam_get_pass)])
    AC_SEARCH_LIBS([pam_get_user], [pam pam_misc])
    AC_SEARCH_LIBS([pam_putenv], [pam pam_misc])
    AC_SEARCH_LIBS([pam_std_option], [pam pam_misc],
        [AC_DEFINE([HAVE_PAM_STD_OPTION], 1,
	    [Define if we have pam_std_option()])],
        [AC_LIBOBJ(pam_std_option)])

    AC_CHECK_TYPE([struct options], AC_DEFINE([HAVE_PAM_STRUCT_OPTIONS], 1,
	[Define if PAM uses struct options]),,
	    [#include <pam_modules.h>
#include <pam_mod_misc.h>])
    AC_CHECK_TYPE([struct opttab], AC_DEFINE([HAVE_PAM_STRUCT_OPTTAB], 1,
	[Define if PAM uses struct opttab]),,
	    [#include <pam_modules.h>
#include <pam_mod_misc.h>])

    dnl Find out if we have OpenPAM.

    AC_CHECK_LIB(pam, openpam_log,
	[AC_DEFINE([HAVE_OPENPAM], 1, [Define if we have OpenPAM])])

    dnl Supply our own OpenPAM cred functions if this system's PAM
    dnl doesn't implement them.  Other systems implement them but
    dnl don't declare them.

    AC_CHECK_DECLS([openpam_borrow_cred, openpam_restore_cred])
    AC_REPLACE_FUNCS(openpam_borrow_cred openpam_restore_cred)

    dnl Do we use const void *, or just void *?

    AC_MSG_CHECKING(whether PAM prototypes use const pointers)
    AC_EGREP_HEADER([const void \*\*item], security/pam_appl.h,
        [AC_DEFINE(HAVE_PAM_CONST_PROTO, 1,
	    [Define if PAM prototypes use const pointers]) AC_MSG_RESULT(yes)],
        AC_MSG_RESULT(no))

    AC_SUBST(PAMDIR) 
])dnl
