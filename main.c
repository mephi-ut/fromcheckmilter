
// === Includes ===

#define _GNU_SOURCE

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <netdb.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>
#include <libmilter/mfapi.h>
#include <syslog.h>

// === Global definitions ===

enum flags {
	FLAG_EMPTY		= 0x00,
	FLAG_CHECK_MAILFROM	= 0x01,
};
typedef enum flags flags_t;
flags_t flags = FLAG_EMPTY;

// === Code ===

extern sfsistat fromckmilter_cleanup(SMFICTX *, bool);

sfsistat fromckmilter_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_helo(SMFICTX *ctx, char *helohost) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_envfrom(SMFICTX *ctx, char **argv) {
	if(flags & FLAG_CHECK_MAILFROM) {
		if(argv[0] == NULL) {
			syslog(LOG_NOTICE, "fromckmilter_envfrom(): argv[0]==NULL. Sending TEMPFAIL.\n");
			return SMFIS_TEMPFAIL;
		}
		if(*argv[0] == 0) {
			syslog(LOG_NOTICE, "fromckmilter_envfrom(): *argv[0]==0. Sending TEMPFAIL.\n");
			return SMFIS_TEMPFAIL;
		}

		char *mailfrom = strdup(argv[0]);
		smfi_setpriv(ctx, mailfrom);
	}

	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_envrcpt(SMFICTX *ctx, char **argv) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_header(SMFICTX *ctx, char *headerf, char *headerv) {

	if(!strcasecmp(headerf, "From")) {
		char *domainname_mailfrom=NULL, *domainname_from;

		// "MAIL FROM"
		if(flags & FLAG_CHECK_MAILFROM) {

			// Getting MAIL FROM value

			char *mailfrom = smfi_getpriv(ctx);

			if(mailfrom == NULL) {
				syslog(LOG_NOTICE, "fromckmilter_header(): mailfrom==NULL. Sending TEMPFAIL.\n");
				return SMFIS_TEMPFAIL;
			}
			if(*mailfrom == 0) {
				syslog(LOG_NOTICE, "fromckmilter_header(): *mailfrom==0. Sending TEMPFAIL.\n");
				return SMFIS_TEMPFAIL;
			}

			// Getting domain name from MAIL FROM value

			char *at = strchr(mailfrom, '@');
			if(!at) {
				syslog(LOG_NOTICE, "%s: Invalid \"MAIL FROM\" value: no \"@\" in the string: \"%s\"\n",
					smfi_getsymval(ctx, "i"), mailfrom);
				return SMFIS_REJECT;        // No "@" in "From:" value
			}

			domainname_mailfrom = &at[1];
			if(!domainname_mailfrom[0]) {                // Empty after "@" in "From:" value
				syslog(LOG_NOTICE, "%s: Invalid \"MAIL FROM\" value: empty after the \"@\": \"%s\"\n",
					smfi_getsymval(ctx, "i"), mailfrom);
				return SMFIS_REJECT;
			}

			// Cutting the domain name of MAIL FROM value

			char *strtok_saveptr = NULL;
			char *domainname_cut = strtok_r(domainname_mailfrom, " \t)(<>@,;:\"/[]?=", &strtok_saveptr);
			if(domainname_cut != NULL)
				domainname_mailfrom = domainname_cut;
		}

		// "From"

		{

			// Checking the domain name: getting the domain name

			char *at = strchr(headerv, '@');
			if(!at) {
				syslog(LOG_NOTICE, "%s: Invalid \"from\" value: no \"@\" in the string: \"%s\"\n",
					smfi_getsymval(ctx, "i"), headerv);
				return SMFIS_REJECT;        // No "@" in "From:" value
			}

			domainname_from = &at[1];
			if(!domainname_from[0]) {                // Empty after "@" in "From:" value
				syslog(LOG_NOTICE, "%s: Invalid \"from\" value: empty after the \"@\": \"%s\"\n",
					smfi_getsymval(ctx, "i"), headerv);
				return SMFIS_REJECT;
			}

			// Checking the domain name: Cutting the domain name

			char *strtok_saveptr = NULL;
			char *domainname_cut = strtok_r(domainname_from, " \t)(<>@,;:\"/[]?=", &strtok_saveptr);
			if(domainname_cut != NULL)
				domainname_from = domainname_cut;

			// Checking the domain name

#ifdef METHOD_GETADDRINFO
			// Deprecated method: Resolves A-record, but MX is required

			struct addrinfo *res;
			if(getaddrinfo(domainname_from, NULL, NULL, &res))
#else
			// Good method.
			unsigned char answer[BUFSIZ];
			int answer_len = res_search(domainname_from, C_IN, T_MX, answer, BUFSIZ);

			if(answer_len == -1) {
				syslog(LOG_NOTICE, "%s: Unable to resolve MX-record of domain name \"%s\". Unusual for mail server.\n",
					smfi_getsymval(ctx, "i"), domainname_from);
				answer_len = res_search(domainname_from, C_IN, T_A, answer, BUFSIZ);
			}

			if(answer_len == -1)
				answer_len = res_search(domainname_from, C_IN, T_AAAA, answer, BUFSIZ);

			if(answer_len == -1)
#endif
			{
				syslog(LOG_NOTICE, "%s: Unable to resolve domain name \"%s\" from \"From\" value: \"%s\". Answering TEMPFAIL.\n", 
					smfi_getsymval(ctx, "i"), domainname_from, headerv);
				return SMFIS_TEMPFAIL;        // Non existant domain name in "From:" value
			}

		}

		if(flags & FLAG_CHECK_MAILFROM) {
			char *result;
			size_t domainname_from_len, domainname_mailfrom_len;

			domainname_from_len     = strlen(domainname_from);
			domainname_mailfrom_len = strlen(domainname_mailfrom);

			if(domainname_from_len > domainname_mailfrom_len)
				result = strcasestr(domainname_from, domainname_mailfrom);
			else
				result = strcasestr(domainname_mailfrom, domainname_from);

			if(result == NULL) {
				syslog(LOG_NOTICE, "%s: \"MAIL FROM\" !~ \"From\": \"%s\" !~ \"%s\". Sending REJECT.\n",
					smfi_getsymval(ctx, "i"), domainname_mailfrom, domainname_from);
				return SMFIS_REJECT;
			}
		}

	}
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_eoh(SMFICTX *ctx) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_body(SMFICTX *ctx, unsigned char *bodyp, size_t bodylen) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_eom(SMFICTX *ctx) {
	smfi_addheader(ctx, "X-FromChk-Milter", "passed");

	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_abort(SMFICTX *ctx) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_close(SMFICTX *ctx) {
	char *mailfrom = smfi_getpriv(ctx);
	if(mailfrom != NULL) {
		free(mailfrom);
		smfi_setpriv(ctx, NULL);
	}

	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_unknown(SMFICTX *ctx, const char *cmd) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_data(SMFICTX *ctx) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_negotiate(ctx, f0, f1, f2, f3, pf0, pf1, pf2, pf3)
	SMFICTX *ctx;
	unsigned long f0;
	unsigned long f1;
	unsigned long f2;
	unsigned long f3;
	unsigned long *pf0;
	unsigned long *pf1;
	unsigned long *pf2;
	unsigned long *pf3;
{
	return SMFIS_ALL_OPTS;
}

static void usage(const char *path) {
	fprintf(stderr, "Usage: %s -p socket-addr [-t timeout]\n",
		path);
}

int main(int argc, char *argv[]) {
	struct smfiDesc mailfilterdesc = {
		"FromCheckMilter",		// filter name
		SMFI_VERSION,			// version code -- do not change
		SMFIF_ADDHDRS|SMFIF_ADDRCPT,	// flags
		fromckmilter_connect,		// connection info filter
		fromckmilter_helo,		// SMTP HELO command filter
		fromckmilter_envfrom,		// envelope sender filter
		fromckmilter_envrcpt,		// envelope recipient filter
		fromckmilter_header,		// header filter
		fromckmilter_eoh,		// end of header
		fromckmilter_body,		// body block filter
		fromckmilter_eom,		// end of message
		fromckmilter_abort,		// message aborted
		fromckmilter_close,		// connection cleanup
		fromckmilter_unknown,		// unknown SMTP commands
		fromckmilter_data,		// DATA command
		fromckmilter_negotiate		// Once, at the start of each SMTP connection
	};

	if (res_init() != 0) {
		fprintf(stderr, "Error while res_init()\n");
		exit(EX_SOFTWARE);
	}

	char setconn = 0;
	int c;
	const char *args = "p:t:hm";
	extern char *optarg;
	// Process command line options
	while ((c = getopt(argc, argv, args)) != -1) {
		switch (c) {
			case 'p':
				if (optarg == NULL || *optarg == '\0')
				{
					(void)fprintf(stderr, "Illegal conn: %s\n",
						optarg);
					exit(EX_USAGE);
				}
				if (smfi_setconn(optarg) == MI_FAILURE)
				{
					(void)fprintf(stderr,
						"smfi_setconn failed\n");
					exit(EX_SOFTWARE);
				}

				if (strncasecmp(optarg, "unix:", 5) == 0)
					unlink(optarg + 5);
				else if (strncasecmp(optarg, "local:", 6) == 0)
					unlink(optarg + 6);
				setconn = 1;
				break;
			case 't':
				if (optarg == NULL || *optarg == '\0') {
					(void)fprintf(stderr, "Illegal timeout: %s\n", 
						optarg);
					exit(EX_USAGE);
				}
				if (smfi_settimeout(atoi(optarg)) == MI_FAILURE) {
					(void)fprintf(stderr,
						"smfi_settimeout failed\n");
					exit(EX_SOFTWARE);
				}
				break;
			case 'm':
				flags |= FLAG_CHECK_MAILFROM;
				break;
			case 'h':
			default:
				usage(argv[0]);
				exit(EX_USAGE);
		}
	}
	if (!setconn) {
		fprintf(stderr, "%s: Missing required -p argument\n", argv[0]);
		usage(argv[0]);
		exit(EX_USAGE);
	}
	if (smfi_register(mailfilterdesc) == MI_FAILURE) {
		fprintf(stderr, "smfi_register failed\n");
		exit(EX_UNAVAILABLE);
	}
	openlog(NULL, LOG_PID, LOG_MAIL);
	int ret = smfi_main();
	closelog();
	return ret;
}

