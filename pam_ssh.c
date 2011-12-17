/*-
 * Copyright (c) 1999-2002, 2004, 2007 Andrew J. Korty
 * All rights reserved.
 *
 * Copyright (c) 2001, 2002 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * Portions of this software were developed for the FreeBSD Project by
 * ThinkSec AS and NAI Labs, the Security Research Division of Network
 * Associates, Inc.  under DARPA/SPAWAR contract N66001-01-C-8035
 * ("CBOSS"), as part of the DARPA CHATS research program.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $Id: pam_ssh.c,v 1.83 2007/02/06 18:10:46 akorty Exp $
 */

/* to get the asprintf() prototype from the glibc headers */
#define _GNU_SOURCE

#include <sys/cdefs.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <config.h>
#if HAVE_SYS_WAIT_H
# include <sys/wait.h>
#endif
#ifndef WEXITSTATUS
# define WEXITSTATUS(x)	((unsigned)(x) >> 8)
#endif
#ifndef WTERMSIG
# define WTERMSIG(x)	((x) & 0177)
#endif
#ifndef WIFSIGNALED
# define WIFSIGNALED(x)	(WTERMSIG(x) != _WSTOPPED && WTERMSIG(x) != 0)
#endif

#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#define PAM_SM_AUTH
#define PAM_SM_SESSION
#if !HAVE_OPENPAM
# define PAM_SM_ACCOUNT
# define PAM_SM_PASSWORD
#endif

#include <pam_modules.h>
#if HAVE_PAM_MOD_MISC_H
# include <pam_mod_misc.h>
#endif

#include <openssl/dsa.h>
#include <openssl/evp.h>

#include "key.h"
#include "authfd.h"
#include "authfile.h"
#include "log.h"
#if !HAVE_DECL_OPENPAM_BORROW_CRED || !HAVE_DECL_OPENPAM_RESTORE_CRED
# include "openpam_cred.h"
#endif
#if !HAVE_PAM_STRUCT_OPTTAB
# include "pam_opttab.h"
#endif
#if !HAVE_PAM_STD_OPTION && !HAVE_OPENPAM
# include "pam_option.h"
#endif
#if !HAVE_PAM_GET_PASS
# include "pam_get_pass.h"
#endif

#if !defined(__unused)
# define __unused
#endif

#define	MODULE_NAME			"pam_ssh"
#define	NEED_PASSPHRASE			"SSH passphrase: "
#define DEF_KEYFILES			"id_dsa,id_rsa,identity"
#define ENV_PID_SUFFIX			"_AGENT_PID"
#define ENV_SOCKET_SUFFIX		"_AUTH_SOCK"
#define PAM_OPT_KEYFILES_NAME		"keyfiles"
#define PAM_OPT_BLANK_PASSPHRASE_NAME	"allow_blank_passphrase"
#define SEP_KEYFILES			","
#define SSH_CLIENT_DIR			".ssh"

enum {
#if HAVE_OPENPAM || HAVE_PAM_STRUCT_OPTIONS || !HAVE_PAM_STD_OPTION
	PAM_OPT_KEYFILES = PAM_OPT_STD_MAX,
	PAM_OPT_BLANK_PASSPHRASE
#else
	PAM_OPT_KEYFILES,
	PAM_OPT_BLANK_PASSPHRASE
#endif
};

static struct opttab other_options[] = {
	{ PAM_OPT_KEYFILES_NAME,		PAM_OPT_KEYFILES },
	{ PAM_OPT_BLANK_PASSPHRASE_NAME,	PAM_OPT_BLANK_PASSPHRASE },
	{ NULL, 0 }
};

char *
opt_arg(const char *arg)
{
	char *retval;

	if (!(retval = strchr(arg, '=')))
		return retval;
	++retval;
	return retval;
}

/*
 * Generic logging function that tags a message with the module name,
 * saving errno so it doesn't get whacked by asprintf().
 */

static void
pam_ssh_log(int priority, const char *fmt, ...)
{
	va_list ap;		/* variable argument list */
	int errno_saved;	/* for caching errno */
	char *tagged;		/* format tagged with module name */

	errno_saved = errno;
	asprintf(&tagged, "%s: %s", MODULE_NAME, fmt);
	va_start(ap, fmt);
	errno = errno_saved;
	vsyslog(priority, tagged ? tagged : fmt, ap);
	free(tagged);
	va_end(ap);
}


pid_t
waitpid_intr(pid_t pid, int *status, int options)
{
	pid_t retval;

	do {
		retval = waitpid(pid, status, options);
	} while (retval == -1 && errno == EINTR);
	return retval;
}


/*
 * Generic cleanup function for OpenSSH "Key" type.
 */

static void
key_cleanup(pam_handle_t *pamh __unused, void *data, int err __unused)
{
	if (data)
		key_free(data);
}


/*
 * Generic PAM cleanup function for this module.
 */

static void
ssh_cleanup(pam_handle_t *pamh __unused, void *data, int err __unused)
{
	if (data)
		free(data);
}


/*
 * If the private key's passphrase is blank, only load it if the
 * *supplied* passphrase is blank and if allow_blank_passphrase is
 * set.
 */

static Key *
key_load_private_maybe(const char *path, const char *passphrase,
    char **commentp, int allow_blank)
{
        Key *key;

        /* try loading the key with a blank passphrase */
        key = key_load_private(path, "", commentp);
        if (key)
                return allow_blank && *passphrase == '\0' ? key : NULL;

        /* the private key's passphrase isn't blank */
        return key_load_private(path, passphrase, commentp);
}

/*
 * Authenticate a user's key by trying to decrypt it with the password
 * provided.  The key and its comment are then stored for later
 * retrieval by the session phase.  An increasing index is embedded in
 * the PAM variable names so this function may be called multiple times
 * for multiple keys.
 */

static int
auth_via_key(pam_handle_t *pamh, const char *file, const char *dir,
    const struct passwd *user, const char *pass, int allow_blank)
{
	char *comment;		/* private key comment */
	char *data_name;	/* PAM state */
	static int index = 0;	/* for saved keys */
	Key *key;		/* user's key */
	char *path;		/* to key files */
	int retval;		/* from calls */

	/* an int only goes so far */

	if (index < 0)
		return PAM_SERVICE_ERR;
	  
	/* locate the user's private key file */

	if (asprintf(&path, "%s/%s", dir, file) == -1) {
		pam_ssh_log(LOG_CRIT, "out of memory");
		return PAM_SERVICE_ERR;
	}

	/* Try to decrypt the private key with the passphrase provided.  If
	   success, the user is authenticated. */

	comment = NULL;
	key = key_load_private_maybe(path, pass, &comment, allow_blank);
	free(path);
	if (!comment && !(comment = strdup(file))) {
		pam_ssh_log(LOG_CRIT, "out of memory");
		return PAM_SERVICE_ERR;
	}
	if (!key) {
		free(comment);
		return PAM_AUTH_ERR;
	}

	/* save the key and comment to pass to ssh-agent in the session
           phase */

	if (asprintf(&data_name, "ssh_private_key_%d", index) == -1) {
		free(comment);
		pam_ssh_log(LOG_CRIT, "out of memory");
		return PAM_SERVICE_ERR;
	}
	retval = pam_set_data(pamh, data_name, key, key_cleanup);
	free(data_name);
	if (retval != PAM_SUCCESS) {
		key_free(key);
		free(comment);
		return retval;
	}
	if (asprintf(&data_name, "ssh_key_comment_%d", index) == -1) {
		pam_ssh_log(LOG_CRIT, "out of memory");
		free(comment);
		return PAM_SERVICE_ERR;
	}
	retval = pam_set_data(pamh, data_name, comment, ssh_cleanup);
	free(data_name);
	if (retval != PAM_SUCCESS) {
		free(comment);
		return retval;
	}

	++index;
	return PAM_SUCCESS;
}


/*
 * Add the keys stored by auth_via_key() to the agent connected to the
 * socket provided.
 */

static int
add_keys(pam_handle_t *pamh, char *socket)
{
	AuthenticationConnection *ac;	/* connection to ssh-agent */
	char *comment;			/* private key comment */
	char *data_name;		/* PAM state */
	int final;			/* final return value */
	int index;			/* for saved keys */
	Key *key;			/* user's private key */
	int retval;			/* from calls */

	/* connect to the agent */

	if (!(ac = ssh_get_authentication_connection(socket))) {
		pam_ssh_log(LOG_ERR, "%s: %m", socket);
		return PAM_SESSION_ERR;
	}

	/* hand off each private key to the agent */

	final = 0;
	for (index = 0; index >= 0; index++) {
		if (asprintf(&data_name, "ssh_private_key_%d", index) == -1) {
			pam_ssh_log(LOG_CRIT, "out of memory");
			ssh_close_authentication_connection(ac);
			return PAM_SERVICE_ERR;
		}
		retval = pam_get_data(pamh, data_name,
		    (const void **)(void *)&key);
		free(data_name);
		if (retval != PAM_SUCCESS)
			break;
		if (asprintf(&data_name, "ssh_key_comment_%d", index) == -1) {
			pam_ssh_log(LOG_CRIT, "out of memory");
			ssh_close_authentication_connection(ac);
			return PAM_SERVICE_ERR;
		}
		retval = pam_get_data(pamh, data_name,
		    (const void **)(void *)&comment);
		free(data_name);
		if (retval != PAM_SUCCESS)
			break;
		retval = ssh_add_identity(ac, key, comment);
		if (!final)
			final = retval;
	}
	ssh_close_authentication_connection(ac);

	return final ? PAM_SUCCESS : PAM_SESSION_ERR;
}


PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags __unused, int argc,
    const char **argv)
{
	int allow_blank_passphrase;	/* allow blank passphrases? */
	int authenticated;		/* user authenticated? */
	char *dotdir;			/* .ssh dir name */
	char *file;			/* current key file */
	char *keyfiles;			/* list of key files to add */
#if HAVE_OPENPAM
	const char *kfspec;		/* list of key files to add */
#elif HAVE_PAM_STRUCT_OPTIONS || !HAVE_PAM_STD_OPTION
	char *kfspec;			/* list of key files to add */
	struct options options;		/* options for pam_get_pass() */
#else
	char *kfspec;			/* list of key files to add */
	int options;			/* options for pam_get_pass() */
#endif
	const char *pass;		/* passphrase */
	const struct passwd *pwent;	/* user's passwd entry */
	struct passwd *pwent_keep;	/* our own copy */
	int retval;			/* from calls */
	const char *user;		/* username */

	log_init(MODULE_NAME, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTHPRIV, 0);

	allow_blank_passphrase = 0;
	keyfiles = kfspec = NULL;
#if HAVE_OPENPAM
	if ((kfspec = openpam_get_option(pamh, PAM_OPT_KEYFILES_NAME))) {
		if (!(kfspec = opt_arg(kfspec))) {
			openpam_log(PAM_LOG_ERROR, "invalid keyfile list");
			return PAM_SERVICE_ERR;
		}
	} else
		kfspec = DEF_KEYFILES;
	if ((kfspec = openpam_get_option(pamh, PAM_OPT_BLANK_PASSPHRASE)))
		allow_blank_passphrase = 1;
#elif HAVE_PAM_STRUCT_OPTIONS || !HAVE_PAM_STD_OPTION
	memset(&options, 0, sizeof options);
	pam_std_option(&options, other_options, argc, argv);
	if (!pam_test_option(&options, PAM_OPT_KEYFILES, &kfspec))
		kfspec = DEF_KEYFILES;
	allow_blank_passphrase =
		pam_test_option(&options, PAM_OPT_BLANK_PASSPHRASE, NULL);
#else
	options = 0;
	for (; argc; argc--, argv++) {
		struct opttab *p;

		for (p = other_options; p->name != NULL; p++) {
			if (strcmp(*argv, p->name) != 0)
				continue;
			switch (p->value) {
			PAM_OPT_KEYFILES:
				if (!(kfspec = opt_arg(*argv))) {
					pam_ssh_log(LOG_ERR,
					    "invalid keyfile list");
					return PAM_SERVICE_ERR;
				}
				break;
			PAM_OPT_BLANK_PASSPHRASE:
				allow_blank_passphrase = 1;
				break;
			}
		}
		pam_std_option(&options, *argv);
	}
	if (!kfspec)
		kfspec = DEF_KEYFILES;
#endif

	if ((retval = pam_get_user(pamh, &user, NULL)) != PAM_SUCCESS)
		return retval;
	if (!(user && (pwent = getpwnam(user)) && pwent->pw_dir &&
	    *pwent->pw_dir))
		return PAM_AUTH_ERR;

	retval = openpam_borrow_cred(pamh, pwent);
	if (retval != PAM_SUCCESS && retval != PAM_PERM_DENIED) {
		pam_ssh_log(LOG_ERR, "can't drop privileges: %m");
		return retval;
	}

	/* pass prompt message to application and receive passphrase */

#if HAVE_OPENPAM
	retval = pam_get_authtok(pamh, PAM_AUTHTOK, &pass, NEED_PASSPHRASE);
#elif HAVE_PAM_STRUCT_OPTIONS || !HAVE_PAM_STD_OPTION
	retval = pam_get_pass(pamh, &pass, NEED_PASSPHRASE, &options);
#else
	retval = pam_get_pass(pamh, &pass, NEED_PASSPHRASE, options);
#endif
	if (retval != PAM_SUCCESS) {
		openpam_restore_cred(pamh);
		return retval;
	}
	if (!pass) {
		openpam_restore_cred(pamh);
		return PAM_AUTH_ERR;
	}

	OpenSSL_add_all_algorithms(); /* required for DSA */

	/* any key will authenticate us, but if we can decrypt all of the
           specified keys, we'll do so here so we can cache them in the
           session phase */

	if (asprintf(&dotdir, "%s/%s", pwent->pw_dir, SSH_CLIENT_DIR) == -1) {
		pam_ssh_log(LOG_CRIT, "out of memory");
		openpam_restore_cred(pamh);
		return PAM_SERVICE_ERR;
	}
	authenticated = 0;
	if (!(keyfiles = strdup(kfspec))) {
		pam_ssh_log(LOG_CRIT, "out of memory");
		openpam_restore_cred(pamh);
		return PAM_SERVICE_ERR;
	}
	for (file = strtok(keyfiles, SEP_KEYFILES); file;
	     file = strtok(NULL, SEP_KEYFILES))
		if (auth_via_key(pamh, file, dotdir, pwent, pass,
                    allow_blank_passphrase) == PAM_SUCCESS)
			authenticated = 1;
	free(dotdir);
	free(keyfiles);
	if (!authenticated) {
		openpam_restore_cred(pamh);
		return PAM_AUTH_ERR;
	}

	/* copy the passwd entry (in case successive calls are made) and
           save it for the session phase */

	if (!(pwent_keep = malloc(sizeof *pwent))) {
		pam_ssh_log(LOG_CRIT, "out of memory");
		openpam_restore_cred(pamh);
		return PAM_SERVICE_ERR;
	}
	memcpy(pwent_keep, pwent, sizeof *pwent_keep);
	if ((retval = pam_set_data(pamh, "ssh_passwd_entry", pwent_keep,
	    ssh_cleanup)) != PAM_SUCCESS) {
		free(pwent_keep);
		openpam_restore_cred(pamh);
		return retval;
	}

	openpam_restore_cred(pamh);
	return PAM_SUCCESS;
}


PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	return PAM_SUCCESS;
}


PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	char *agent_pid;		/* copy of agent PID */
	char *agent_socket;		/* agent socket */
	char *arg[3], *env[1];		/* to pass to execve() */
	pid_t child_pid;		/* child process that spawns agent */
	int child_pipe[2];		/* pipe to child process */
	int child_status;		/* child process status */
	char *cp;			/* scratch */
	char *env_end;			/* end of env */
	FILE *env_read;			/* env data source */
	char env_string[BUFSIZ];	/* environment string */
	char *env_value;		/* envariable value */
	int env_write;			/* env file descriptor */
	char hname[MAXHOSTNAMELEN];	/* local hostname */
	int no_link;			/* link per-agent file? */
	char *per_agent;		/* to store env */
	char *per_session;		/* per-session filename */
	const struct passwd *pwent;	/* user's passwd entry */
	int retval;			/* from calls */
	int start_agent;		/* start agent? */
	const char *tty_raw;		/* raw tty or display name */
	char *tty_nodir;		/* tty without / chars */

	log_init(MODULE_NAME, SYSLOG_LEVEL_ERROR, SYSLOG_FACILITY_AUTHPRIV, 0);

	/* dump output of ssh-agent in ~/.ssh */
	if ((retval = pam_get_data(pamh, "ssh_passwd_entry",
	    (const void **)(void *)&pwent))
	    != PAM_SUCCESS)
		return retval;

	retval = openpam_borrow_cred(pamh, pwent);
	if (retval != PAM_SUCCESS && retval != PAM_PERM_DENIED) {
		pam_ssh_log(LOG_ERR, "can't drop privileges: %m");
		return retval;
	}

	/*
	 * Use reference counts to limit agents to one per user per host.
	 *
	 * Technique: Create an environment file containing
	 * information about the agent.  Only one file is created, but
	 * it may be given many names.  One name is given for the
	 * agent itself, agent-<host>.  Another name is given for each
	 * session, agent-<host>-<display> or agent-<host>-<tty>.  We
	 * delete the per-session filename on session close, and when
	 * the link count goes to unity on the per-agent file, we
	 * delete the file and kill the agent.
	 */

	/* the per-agent file contains just the hostname */

	gethostname(hname, sizeof hname);
	if (asprintf(&per_agent, "%s/.ssh/agent-%s", pwent->pw_dir, hname)
	    == -1) {
		pam_ssh_log(LOG_CRIT, "out of memory");
		openpam_restore_cred(pamh);
		return PAM_SERVICE_ERR;
	}

	/* save the per-agent filename in case we want to delete it on
           session close */

	if ((retval = pam_set_data(pamh, "ssh_agent_env_agent", per_agent,
	    ssh_cleanup)) != PAM_SUCCESS) {
		free(per_agent);
		openpam_restore_cred(pamh);
		return retval;
	}

	/* Try to create the per-agent file or open it for reading if it
           exists.  If we can't do either, we won't try to link a
           per-session filename later.  Start the agent if we can't open
	   the file for reading. */

	env_write = child_pid = no_link = start_agent = 0;
	env_read = NULL;
	if ((env_write = open(per_agent, O_CREAT | O_EXCL | O_WRONLY, S_IRUSR))
	    < 0 && !(env_read = fopen(per_agent, "r")))
		no_link = 1;
	if (!env_read) {
		start_agent = 1;
		if (pipe(child_pipe) < 0) {
			pam_ssh_log(LOG_ERR, "pipe: %m");
			close(env_write);
			openpam_restore_cred(pamh);
			return PAM_SERVICE_ERR;
		}
		switch (child_pid = fork()) {
		case -1:	/* error */
			pam_ssh_log(LOG_ERR, "fork: %m");
			close(child_pipe[0]);
			close(child_pipe[1]);
			close(env_write);
			openpam_restore_cred(pamh);
			return PAM_SERVICE_ERR;
			/* NOTREACHED */
		case 0:		/* child */

			/* Permanently drop privileges using setuid()
			   before executing ssh-agent so that root
			   privileges can't possibly be regained (some
			   ssh-agents insist that euid == ruid
			   anyway).  System V won't let us use
			   setuid() unless euid == 0, so we
			   temporarily regain root privileges first
			   with openpam_restore_cred() (which calls
			   seteuid()). */

			switch (openpam_restore_cred(pamh)) {
			case PAM_SYSTEM_ERR:
				pam_ssh_log(LOG_ERR,
				    "can't restore privileges: %m");
				_exit(EX_OSERR);
				/* NOTREACHED */
			case PAM_SUCCESS:
				if (setuid(pwent->pw_uid) == -1) {
					pam_ssh_log(LOG_ERR,
					    "can't drop privileges: %m",
					    pwent->pw_uid);
					_exit(EX_NOPERM);
				}
				break;
			}

			if (close(child_pipe[0]) == -1) {
				pam_ssh_log(LOG_ERR, "close: %m");
				_exit(EX_OSERR);
			}
			if (child_pipe[1] != STDOUT_FILENO) {
				if (dup2(child_pipe[1], STDOUT_FILENO) == -1) {
					pam_ssh_log(LOG_ERR, "dup: %m");
					_exit(EX_OSERR);
				}
				if (close(child_pipe[1]) == -1) {
					pam_ssh_log(LOG_ERR, "close: %m");
					_exit(EX_OSERR);
				}
			}
			arg[0] = "ssh-agent";
			arg[1] = "-s";
			arg[2] = NULL;
			env[0] = NULL;
			execve(PATH_SSH_AGENT, arg, env);
			pam_ssh_log(LOG_ERR, "%s: %m", PATH_SSH_AGENT);
			_exit(127);
			/* NOTREACHED */
		}
		if (close(child_pipe[1]) == -1) {
			pam_ssh_log(LOG_ERR, "close: %m");
			openpam_restore_cred(pamh);
			return PAM_SESSION_ERR;
		}
		if (!(env_read = fdopen(child_pipe[0], "r"))) {
			pam_ssh_log(LOG_ERR, "%s: %m", PATH_SSH_AGENT);
			close(env_write);
			openpam_restore_cred(pamh);
			return PAM_SESSION_ERR;
		}
	}

	/* save environment for application with pam_putenv() */

	agent_socket = NULL;
	while (fgets(env_string, sizeof env_string, env_read)) {

		/* parse environment definitions */

		if (env_write >= 0)
			write(env_write, env_string, strlen(env_string));
		if (!(env_value = strchr(env_string, '=')) ||
		    !(env_end = strchr(env_value, ';')))
			continue;
		*env_end = '\0';

		/* pass to the application */

		if ((retval = pam_putenv(pamh, env_string)) != PAM_SUCCESS) {
			fclose(env_read);
			if (start_agent)
				waitpid_intr(child_pid, &child_status, 0);
			close(env_write);
			if (agent_socket)
				free(agent_socket);
			openpam_restore_cred(pamh);
			return retval;
		}

		*env_value++ = '\0';

		/* save the agent socket so we can connect to it and add
                   the keys as well as the PID so we can kill the agent on
                   session close. */

		agent_pid = NULL;
		if (strcmp(&env_string[strlen(env_string) -
		    strlen(ENV_SOCKET_SUFFIX)], ENV_SOCKET_SUFFIX) == 0 &&
		    !(agent_socket = strdup(env_value))) {
			pam_ssh_log(LOG_CRIT, "out of memory");
			fclose(env_read);
			if (start_agent)
				waitpid_intr(child_pid, &child_status, 0);
			close(env_write);
			if (agent_socket)
				free(agent_socket);
			openpam_restore_cred(pamh);
			return PAM_SERVICE_ERR;
		} else if (strcmp(&env_string[strlen(env_string) -
		    strlen(ENV_PID_SUFFIX)], ENV_PID_SUFFIX) == 0 &&
		    (!(agent_pid = strdup(env_value)) ||
		    (retval = pam_set_data(pamh, "ssh_agent_pid",
		    agent_pid, ssh_cleanup)) != PAM_SUCCESS)) {
			fclose(env_read);
			if (start_agent)
				waitpid_intr(child_pid, &child_status, 0);
			close(env_write);
			if (agent_pid)
				free(agent_pid);
			else {
				pam_ssh_log(LOG_CRIT, "out of memory");
				openpam_restore_cred(pamh);
				return PAM_SERVICE_ERR;
			}
			if (agent_socket)
				free(agent_socket);
			openpam_restore_cred(pamh);
			return retval;
		}

	}
	close(env_write);

	if (fclose(env_read) != 0) {
		pam_ssh_log(LOG_ERR, "fclose: %m");
		openpam_restore_cred(pamh);
		return PAM_SESSION_ERR;
	}

	if (start_agent) {

		/* Ignore ECHILD in case a SIGCHLD handler is installed. */

		child_status = 0;
		if (waitpid_intr(child_pid, &child_status, 0) == -1 &&
		    errno != ECHILD) {
			pam_ssh_log(LOG_ERR, "%s: %m", PATH_SSH_AGENT);
			if (agent_socket)
				free(agent_socket);
			openpam_restore_cred(pamh);
			return PAM_SESSION_ERR;
		}

		if (child_status != 0) {
			if (WIFSIGNALED(child_status))
				pam_ssh_log(LOG_ERR, "%s exited on signal %d",
				    PATH_SSH_AGENT, WTERMSIG(child_status));
			else
				if (WEXITSTATUS(retval) == 127)
					pam_ssh_log(LOG_ERR,
					    "cannot execute %s",
					    PATH_SSH_AGENT);
				else
					pam_ssh_log(LOG_ERR,
					    "%s exited with status %d",
					    PATH_SSH_AGENT,
					    WEXITSTATUS(child_status));
			if (agent_socket)
				free(agent_socket);
			openpam_restore_cred(pamh);
			return PAM_SESSION_ERR;
		}
	}

	if (!agent_socket) {
		openpam_restore_cred(pamh);
		return PAM_SESSION_ERR;
	}

	if (start_agent && (retval = add_keys(pamh, agent_socket))
	    != PAM_SUCCESS) {
		openpam_restore_cred(pamh);
		return retval;
	}
	free(agent_socket);

	/* if we couldn't access the per-agent file, don't link a
           per-session filename to it */

	if (no_link) {
		openpam_restore_cred(pamh);
		return PAM_SUCCESS;
	}

	/* the per-session file contains the display name or tty name as
           well as the hostname */

	if ((retval = pam_get_item(pamh, PAM_TTY,
	    (const void **)(void *)&tty_raw)) != PAM_SUCCESS) {
		openpam_restore_cred(pamh);
		return retval;
	}

	/* set tty_nodir to the tty with / replaced by _ */

	if (!(tty_nodir = strdup(tty_raw))) {
		pam_ssh_log(LOG_CRIT, "out of memory");
		openpam_restore_cred(pamh);
		return PAM_SERVICE_ERR;
	}
	for (cp = tty_nodir; (cp = strchr(cp, '/')); )
		*cp = '_';

	if (asprintf(&per_session, "%s/.ssh/agent-%s-%s", pwent->pw_dir, hname,
	    tty_nodir) == -1) {
		pam_ssh_log(LOG_CRIT, "out of memory");
		free(tty_nodir);
		openpam_restore_cred(pamh);
		return PAM_SERVICE_ERR;
	}
	free(tty_nodir);

	/* save the per-session filename so we can delete it on session
           close */

	if ((retval = pam_set_data(pamh, "ssh_agent_env_session", per_session,
	    ssh_cleanup)) != PAM_SUCCESS) {
		free(per_session);
		openpam_restore_cred(pamh);
		return retval;
	}

	unlink(per_session);	/* remove cruft */
	link(per_agent, per_session);

	openpam_restore_cred(pamh);
	return PAM_SUCCESS;
}


PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	const char *env_file;		/* ssh-agent environment */
	pid_t pid;			/* ssh-agent process id */
	int retval;			/* from calls */
	const char *ssh_agent_pid;	/* ssh-agent pid string */
	const struct passwd *pwent;	/* user's passwd entry */
	struct stat sb;			/* to check st_nlink */

	if ((retval = pam_get_data(pamh, "ssh_passwd_entry",
	    (const void **)(void *)&pwent)) != PAM_SUCCESS)
		return retval;

	retval = openpam_borrow_cred(pamh, pwent);
	if (retval != PAM_SUCCESS && retval != PAM_PERM_DENIED) {
		pam_ssh_log(LOG_ERR, "can't drop privileges: %m");
		return retval;
	}

	if (pam_get_data(pamh, "ssh_agent_env_session",
	    (const void **)(void *)&env_file) == PAM_SUCCESS && env_file)
		unlink(env_file);

	/* Retrieve per-agent filename and check link count.  If it's
           greater than unity, other sessions are still using this
           agent. */

	if (pam_get_data(pamh, "ssh_agent_env_agent",
	    (const void **)(void *)&env_file)
	    == PAM_SUCCESS && env_file) {
		retval = stat(env_file, &sb);
		if (retval == 0) {
			if (sb.st_nlink > 1) {
				openpam_restore_cred(pamh);
				return PAM_SUCCESS;
			}
			unlink(env_file);
		}
	}

	/* retrieve the agent's process id */

	if ((retval = pam_get_data(pamh, "ssh_agent_pid",
	    (const void **)(void *)&ssh_agent_pid)) != PAM_SUCCESS) {
		openpam_restore_cred(pamh);
		return retval;
	}

	/* Kill the agent.  SSH's ssh-agent does not have a -k option, so
           just call kill(). */

	pid = atoi(ssh_agent_pid);
	if (pid <= 0) {
		openpam_restore_cred(pamh);
		return PAM_SESSION_ERR;
	}
	if (kill(pid, SIGTERM) != 0) {
		pam_ssh_log(LOG_ERR, "%s: %m", ssh_agent_pid);
		openpam_restore_cred(pamh);
		return PAM_SESSION_ERR;
	}

	openpam_restore_cred(pamh);
	return PAM_SUCCESS;
}


#if !HAVE_OPENPAM
PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	return PAM_IGNORE;
}


PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh __unused, int flags __unused,
    int argc __unused, const char **argv __unused)
{
	return PAM_IGNORE;
}
#endif


#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY(MODULE_NAME);
#else /* PAM_MODULE_ENTRY */
#ifdef PAM_STATIC
struct pam_module _modstruct = {
	MODULE_NAME,
	pam_sm_authenticate,
	pam_sm_acct_mgmt,
	pam_sm_chauthtok,
	pam_sm_open_session, pam_sm_close_session,
	NULL
};
#endif /* PAM_STATIC */
#endif /* PAM_MODULE_ENTRY */
