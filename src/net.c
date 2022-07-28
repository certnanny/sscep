
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


/* HTTP routine */

#include "sscep.h"
#include "picohttpparser.h"

#ifdef WIN32
#include <ws2tcpip.h>

void perror_w32 (const char *message)
{
    char buffer[BUFSIZ];

    /* letzten Fehlertext holen und formatieren */
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, (LPSTR) buffer,
		  sizeof buffer, NULL);
    fprintf(stderr, "%s: %s", message, buffer);
}

#define perror perror_w32

#endif

char *url_encode(char *, size_t);
void exit_string_overflow(int);
int http_request(struct http_reply *http, const char* host_name, const char *port_str,
                 const char *http_string, size_t rlen);

int
send_msg(struct http_reply *http, int do_post, char *scep_operation,
		int operation, char *M_char, char *payload, size_t payload_len,
		int p_flag, char *host_name, int host_port, char *dir_name)
{
	char			http_string[16384];
	size_t			rlen;
	char			port_str[6]; /* Range-checked to be max. 5-digit number */
	int ret, fail_count, waited_sec;

	rlen = snprintf(http_string, sizeof(http_string),
		"%s %s%s?operation=%s",
		do_post ? "POST" : "GET", p_flag ? "" : "/", dir_name, scep_operation);
	exit_string_overflow(sizeof(http_string) <= rlen);

	if (!do_post && payload_len > 0) {
		char *encoded = url_encode((char *)payload, payload_len);
		rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
				"&message=%s", encoded);
		free(encoded);
		exit_string_overflow(sizeof(http_string) <= rlen);
	}

	if (M_char != NULL) {
		rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
				"&%s", M_char);
		exit_string_overflow(sizeof(http_string) <= rlen);
	}

	if (host_port == 80) {
		rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
						" HTTP/1.1\r\n"
						"Host: %s\r\n"
						"Connection: close\r\n", host_name);
	} else {
		/* According to RFC2616, non-default port must be added. */
		rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
				" HTTP/1.1\r\n"
				"Host: %s:%d\r\n"
				"Connection: close\r\n", host_name, host_port);
	}
	exit_string_overflow(sizeof(http_string) <= rlen);

	if (do_post) {
		rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
				"Content-Length: %zu\r\n", payload_len);
		exit_string_overflow(sizeof(http_string) <= rlen);
	}

	rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
			"\r\n");
	exit_string_overflow(sizeof(http_string) <= rlen);

	if (do_post) {
		/* concat post data */
		memcpy(http_string+rlen, payload, payload_len);

		rlen += payload_len;
		exit_string_overflow(sizeof(http_string) <= rlen);
	}

	if (d_flag){
		fprintf(stdout, "%s: scep request:\n%s", pname, http_string);
	}

	sprintf(port_str, "%d", host_port);

	fail_count = 0;
	waited_sec = 0;
	/* will retry with linear backoff, just like wget does */
	while (1) {
		ret = http_request(http, host_name, port_str, http_string, rlen);
		if (ret == 0)
			break;
		if (ret == 2 || waited_sec >= W_flag)
			return (1);

		++fail_count;
		if ((waited_sec + fail_count) <= W_flag) {
			sleep(fail_count);
			waited_sec += fail_count;
		} else {
			sleep(W_flag - waited_sec);
			waited_sec = W_flag;
		}
	}

	/* Set SCEP reply type */
	switch (operation) {
		case SCEP_OPERATION_GETCA:
			if (http->mime_type && !strcmp(http->mime_type, MIME_GETCA)) {
				http->type = SCEP_MIME_GETCA;
			} else if (http->mime_type && (!strcmp(http->mime_type, MIME_GETCA_RA) || !strcmp(http->mime_type, MIME_GETCA_RA_ENTRUST))) {
				http->type = SCEP_MIME_GETCA_RA;
			} else {
				goto mime_err;
			}
			break;
		case SCEP_OPERATION_GETNEXTCA:
			if (http->mime_type && !strcmp(http->mime_type, MIME_GETNEXTCA)) {
				http->type = SCEP_MIME_GETNEXTCA;
			} else {
				goto mime_err;
			}
			break;
		case SCEP_OPERATION_GETCAPS:
			/* RFC8894: Clients SHOULD ignore the Content-type, as older
                           implementations of SCEP may send various Content-types. */
			http->type = SCEP_MIME_GETCAPS;
			break;
		default:
			if (http->mime_type && !strcmp(http->mime_type, MIME_PKI)) {
				http->type = SCEP_MIME_PKI;
			} else {
				goto mime_err;
			}
			break;
	}

	return (0);

mime_err:
	if (v_flag)
		fprintf(stderr, "%s: wrong (or missing) MIME content type\n", pname);

	return (1);
}

void exit_string_overflow(int overflow) {
	if (overflow) {
		fprintf(stderr, "%s: not enough buffer space "
				"to construct HTTP request\n", pname);
		exit (SCEP_PKISTATUS_NET);
	}
}

/* URL-encode the input and return back encoded string */
char * url_encode(char *s, size_t n) {
	char	*r;
	size_t	len;
	unsigned int     i;
	char    ch[2];

	/* Allocate 2 times bigger space than the original string */
	len = 2 * n;
	r = (char *)malloc(len);
	if (r == NULL) {
		return NULL;
	}
#ifdef WIN32
	strcpy_s(r, sizeof(r), "");
#else
	strcpy(r, "");
#endif

	/* Copy data */
	for (i = 0; i < n; i++) {
		switch (*(s+i)) {
			case '+':
#ifdef WIN32
				//strncat_s(r, sizeof(r), "%2B", len);
				strncat(r, "%2B", len);
#else
				strncat(r, "%2B", len);
#endif
				break;
			case '-':
#ifdef WIN32
				//strncat_s(r, sizeof(r), "%2D", len);
				strncat(r, "%2D", len);
#else
				strncat(r, "%2D", len);
#endif
				break;
			case '=':
#ifdef WIN32
				//strncat_s(r, sizeof(r), "%3D", len);
				strncat(r, "%3D", len);
#else
				strncat(r, "%3D", len);
#endif
				break;
			case '\n':
#ifdef WIN32
				//strncat_s(r, sizeof(r), "%0A", len);
				strncat(r, "%0A", len);
#else
				strncat(r, "%0A", len);
#endif
				break;
			default:
				ch[0] = *(s+i);
				ch[1] = '\0';
#ifdef WIN32
				//strncat_s(r, sizeof(r), ch, len);
				strncat(r, ch, len);
#else
				strncat(r, ch, len);
#endif
				break;
		}
	}
	r[len-1] = '\0';
	return r;
}

/* returns 0 if successful, 1 on network error, 2 on parse error */
int http_request(struct http_reply *http, const char* host_name, const char *port_str,
                   const char *http_string, size_t rlen)
{
	struct addrinfo hints;
	struct addrinfo *res, *resolve_array;
	int rc, sd, i;

	char *buf;
	int used, bytes, http_chunked;
	int http_minor;
	const char *http_msg;
	size_t msg_size, headers_num, header_size, body_size;
	struct phr_header headers[100];
	struct phr_chunked_decoder http_decoder = {0};
	char *mime_type;
#ifdef WIN32
	int tv=timeout*1000;
#else
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
#endif

	if (v_flag)
		fprintf(stdout, "%s: connecting to %s:%s\n", pname, host_name, port_str);

	/* resolve name */
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = (AI_ADDRCONFIG | AI_V4MAPPED);
	rc = getaddrinfo(host_name, port_str, &hints, &resolve_array);
	if (rc!=0) {
		fprintf(stderr, "failed to resolve remote host address %s (err=%d)\n", host_name, rc);
		return (1);
	}

	/* getaddrinfo() returns a list of address structures.
		Try each address until we successfully connect.
		If socket (or connect) fails, we close the socket
		and try the next address. */
	for (res = resolve_array;
		res != NULL;
		res = resolve_array->ai_next) {
		sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
		if (sd < 0) {
			continue;
		}

		/* connect to server */
		/* The two socket options SO_RCVTIMEO and SO_SNDTIMEO do not work with connect
		connect has a default timeout of 120 */
		rc = connect(sd, res->ai_addr, res->ai_addrlen);
		if (rc < 0) {
			close(sd);
			continue;
		}

		/* connected, exit loop */
		break;
	}

	freeaddrinfo(resolve_array);
	if (!res ) {
		perror("cannot connect");
		return (1);
	}

	setsockopt(sd,SOL_SOCKET, SO_RCVTIMEO,(void *)&tv, sizeof(tv));
	setsockopt(sd,SOL_SOCKET, SO_SNDTIMEO,(void *)&tv, sizeof(tv));

	/* send data */
	rc = send(sd, http_string, rlen, 0);

	if (rc < 0) {
		perror("cannot send data ");
		close(sd);
		return (1);
	}
	else if(rc != rlen)
	{
		fprintf(stderr,"incomplete send\n");
		close(sd);
		return (1);
	}

	/* Get response */
	buf = (char *)malloc(1024);
        used = 0;
        while ((bytes = recv(sd,&buf[used],1024,0)) > 0) {
                used += bytes;
                buf = (char *)realloc(buf, used + 1024);
	}
	if (bytes < 0) {
		perror("error receiving data ");
		close(sd);
		return (1);
	}

	headers_num = sizeof(headers) / sizeof(headers[0]);
	rc = phr_parse_response(buf, used, &http_minor, &http->status,
			&http_msg, &msg_size, headers, &headers_num, 0);
	if (rc < 0) {
		fprintf(stderr,"cannot parse response\n");
		close(sd);
		return (2);
	}
	header_size = rc;

	mime_type = NULL;
	http_chunked = 0;
	for (i = 0; i < headers_num; i++)
	{
		char *ch;
		/* convert to lowercase as some platforms don't have strcasecmp */
		for (ch = (char *)headers[i].name; ch < headers[i].name+headers[i].name_len; ch++)
			*ch = tolower(*ch);

		if (!strncmp("content-type", headers[i].name, headers[i].name_len))
		{
			char *ptr;

			mime_type = (char *)headers[i].value;
			mime_type[headers[i].value_len] = '\0';

			if ((ptr = strchr(mime_type, ';')))
				*ptr = '\0';
		}
		else if (!strncmp("transfer-encoding", headers[i].name, headers[i].name_len) &&
			!strncmp("chunked", headers[i].value, headers[i].value_len))
		{
			http_chunked = 1;
		}
	}

	if (v_flag)
		fprintf(stdout, "%s: server response status code: %d, MIME header: %s\n",
			pname, http->status, mime_type ? mime_type : "missing");

	http->mime_type = mime_type;
	http->payload = buf+header_size;
	body_size = used-header_size;

	if (http_chunked)
	{
		rc = phr_decode_chunked(&http_decoder, http->payload, &body_size);
		if (rc < 0) {
			fprintf(stderr,"%i cannot decode chunked payload\n", rc);
			close(sd);
			return (2);
		}
	}

	http->payload[body_size] = '\0';
	http->bytes = body_size;

#ifdef WIN32
	closesocket(sd);
#else
	close(sd);
#endif
	return (0);
}
