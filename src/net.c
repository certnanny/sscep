
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
void exit_string_overflow(size_t);

int
send_msg(struct http_reply *http, int do_post, char *scep_operation,
		int operation, char *M_char, char *payload, size_t payload_len,
		int p_flag, char *host_name, int host_port, char *dir_name)
{
	char			http_string[16384];
	size_t			rlen;
	int i, sd, rc, used, bytes, http_chunked;
	char *buf, *mime_type;

	char			port_str[6]; /* Range-checked to be max. 5-digit number */
        struct			addrinfo hints;
        struct			addrinfo* res=0;

	int http_minor;
	const char *http_msg;
	size_t msg_size, headers_num, header_size, body_size;
	struct phr_header headers[100];
	struct phr_chunked_decoder http_decoder = {0};
#ifdef WIN32
	int tv=timeout*1000;
#else	
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
#endif

	rlen = snprintf(http_string, sizeof(http_string),
		"%s %s%s?operation=%s",
		do_post ? "POST" : "GET", p_flag ? "" : "/", dir_name, scep_operation);
	exit_string_overflow(sizeof(http_string)-rlen);

	if (!do_post && payload_len > 0) {
		char *encoded = url_encode((char *)payload, payload_len);
		rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
				"&message=%s", encoded);
		free(encoded);
		exit_string_overflow(sizeof(http_string)-rlen);
	}

	if (M_char != NULL) {
		rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
				"&%s", M_char);
		exit_string_overflow(sizeof(http_string)-rlen);
	}

	rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
			" HTTP/1.1\r\n"
			"Host: %s\r\n"
			"Connection: close\r\n", host_name);
	exit_string_overflow(sizeof(http_string)-rlen);

	if (do_post) {
		rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
				"Content-Length: %zd\r\n", payload_len);
		exit_string_overflow(sizeof(http_string)-rlen);
	}

	rlen += snprintf(http_string+rlen, sizeof(http_string)-rlen,
			"\r\n");
	exit_string_overflow(sizeof(http_string)-rlen);

	if (do_post) {
		/* concat post data */
		memcpy(http_string+rlen, payload, payload_len);

		rlen += payload_len;
		exit_string_overflow(sizeof(http_string)-rlen);
	}

	if (d_flag){
		fprintf(stdout, "%s: scep request:\n%s", pname, http_string);
	}

	/* resolve name */
	sprintf(port_str, "%d", host_port);
	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = 0;
	hints.ai_flags = (AI_ADDRCONFIG | AI_V4MAPPED);
	rc = getaddrinfo(host_name, port_str, &hints, &res);
	if (rc!=0) {
		fprintf(stderr, "failed to resolve remote host address %s (err=%d)\n", host_name, rc);
		return (1);
	}

	sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (sd < 0) {
		perror("cannot open socket ");
		freeaddrinfo(res);
		return (1);
	}

	/* connect to server */
	/* The two socket options SO_RCVTIMEO and SO_SNDTIMEO do not work with connect
	   connect has a default timeout of 120 */
	rc = connect(sd, res->ai_addr, res->ai_addrlen);
	freeaddrinfo(res);
	if (rc < 0) {
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
	header_size = phr_parse_response(buf, used, &http_minor, &http->status,
				&http_msg, &msg_size, headers, &headers_num, 0);
	if (header_size < 0) {
		fprintf(stderr,"cannot parse response\n");
		close(sd);
		return (1);
	}

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
			pname, http->status, mime_type);

	http->payload = buf+header_size;
	body_size = used-header_size;

	if (http_chunked)
	{
		rc = phr_decode_chunked(&http_decoder, http->payload, &body_size);
		if (rc < 0) {
			fprintf(stderr,"%i cannot decode chunked payload\n", rc);
			close(sd);
			return (1);
		}
	}

	http->payload[body_size] = '\0';
	http->bytes = body_size;

	/* Set SCEP reply type */
	switch (operation) {
		case SCEP_OPERATION_GETCA:
			if (!strcmp(mime_type, MIME_GETCA)) {
				http->type = SCEP_MIME_GETCA;
			} else if (!strcmp(mime_type, MIME_GETCA_RA) || !strcmp(mime_type, MIME_GETCA_RA_ENTRUST)) {
				http->type = SCEP_MIME_GETCA_RA;
			} else {
				goto mime_err;
			}
			break;
		case SCEP_OPERATION_GETNEXTCA:
			if (!strcmp(mime_type, MIME_GETNEXTCA)) {
				http->type = SCEP_MIME_GETNEXTCA;
			} else {
				goto mime_err;
			}
			break;
		case SCEP_OPERATION_GETCAPS:
			if (!strcmp(mime_type, MIME_GETCAPS)) {
				http->type = SCEP_MIME_GETCAPS;
			} else {
				goto mime_err;
			}
			break;
		default:
			if (strcmp(mime_type, MIME_PKI) != 0) {
				goto mime_err;
			}
			http->type = SCEP_MIME_PKI;
			break;
	}

#ifdef WIN32
	closesocket(sd);
#else
	close(sd);
#endif
	return (0);

mime_err:
	if (v_flag)
		fprintf(stderr, "%s: wrong (or missing) MIME content type\n", pname);

	return (1);
}

void exit_string_overflow(size_t size) {
	if (size <= 0) {
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
