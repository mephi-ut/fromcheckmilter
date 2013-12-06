
// === Includes ===

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

// === Code ===

extern sfsistat fromckmilter_cleanup(SMFICTX *, bool);

sfsistat fromckmilter_connect(SMFICTX *ctx, char *hostname, _SOCK_ADDR *hostaddr) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_helo(SMFICTX *ctx, char *helohost) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_envfrom(SMFICTX *ctx, char **argv) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_envrcpt(SMFICTX *ctx, char **argv) {
	return SMFIS_CONTINUE;
}

sfsistat fromckmilter_header(SMFICTX *ctx, char *headerf, char *headerv) {
	if(!strcasecmp(headerf, "From")) {
		// Checking the domain name: getting the domain name

		char *at = strchr(headerv, '@');
		if(!at) {
			syslog(LOG_NOTICE, "Invalid \"from\" value: no \"@\" in the string: \"%s\"\n", headerv);
			return SMFIS_REJECT;        // No "@" in "From:" value
		}

		char *domainname = &at[1];
		if(!domainname[0]) {                // Empty after "@" in "From:" value
			syslog(LOG_NOTICE, "Invalid \"from\" value: emptry after the \"@\": \"%s\"\n", headerv);
			return SMFIS_REJECT;
		}

		// Checking the domain name: Cutting the domain name

		char *strtok_saveptr = NULL;
		char *domainname_cut = strtok_r(domainname, " \t)(<>@,;:\"/[]?=", &strtok_saveptr);
		if(domainname_cut != NULL)
			domainname = domainname_cut;

		// Checking the domain name

#ifdef METHOD_GETADDRINFO
		// Deprecated method: Resolves A-record, but MX is required

		struct addrinfo *res;
		if(getaddrinfo(domainname, NULL, NULL, &res))
#else
		// Good method.
		unsigned char answer[BUFSIZ];
		int answer_len = res_search(domainname, C_IN, T_MX, answer, BUFSIZ);

		if(answer_len == -1)
#endif
		{
			syslog(LOG_NOTICE, "Unable to resolve domain name \"%s\" from \"from\" value: \"%s\". Answering TEMPFAIL.\n", domainname, headerv);
			return SMFIS_TEMPFAIL;        // Non existant domain name in "From:" value
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
	const char *args = "p:t:h";
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

