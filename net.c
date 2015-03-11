
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


/* HTTP routine */


#include "sscep.h"

#ifdef WIN32
void perror_w32 (const char *message)
{
    char buffer[BUFSIZ];

    /* letzten Fehlertext holen und formatieren */
    FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM, 0, GetLastError(), 0, (LPWSTR) buffer,
		  sizeof buffer, NULL);
    fprintf(stderr, "%s: %s", message, buffer);
}

#define perror perror_w32

#endif

int
send_msg(struct http_reply *http,char *msg,char *host,int port,int operation) {
	int			sd, rc, used, bytes;
	struct sockaddr_in	localAddr, servAddr;
	struct hostent		*h;
	char			tmp[1024], *buf, *p;

#ifdef WIN32
	int tv=timeout*1000;
#else	
	struct timeval tv;
	tv.tv_sec = timeout;
	tv.tv_usec = 0;
#endif

	/* resolve name */
	h = gethostbyname(host);
	if (h == NULL) {
		printf("unknown host '%s'\n", host);
		return (1);
	}

	/* fill in server socket structure: */
	servAddr.sin_family = h->h_addrtype;
	memcpy((char *) &servAddr.sin_addr.s_addr,
		h->h_addr_list[0], h->h_length);
	servAddr.sin_port = htons(port);

	/* create socket */
	sd = socket(AF_INET, SOCK_STREAM, 0);
	if (sd < 0) {
		perror("cannot open socket ");
		return (1);
	}
	/* bind any port number */
	localAddr.sin_family = AF_INET;
	localAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	localAddr.sin_port = htons(0);
	rc = bind(sd, (struct sockaddr *) &localAddr, sizeof(localAddr));
	if (rc < 0) {
		printf("cannot bind port TCP %u\n", port);
		perror("error ");
		return (1);
	}
	
	/* connect to server */
	/* The two socket options SO_RCVTIMEO and SO_SNDTIMEO do not work with connect
	   connect has a default timeout of 120 */
	rc = connect(sd, (struct sockaddr *) &servAddr, sizeof(servAddr));
	if (rc < 0) {
		perror("cannot connect");
		return (1);
	}
	setsockopt(sd,SOL_SOCKET, SO_RCVTIMEO,(void *)&tv, sizeof(tv));
	setsockopt(sd,SOL_SOCKET, SO_SNDTIMEO,(void *)&tv, sizeof(tv));
	/* send data */ 
	rc = send(sd, msg,strlen(msg), 0);

	if (rc < 0) {
		perror("cannot send data ");
		close(sd);
		return (1);
	}
	else if(rc != strlen(msg))
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
        buf[used] = '\0';
		
	
	/* Fetch the status code: */
	#ifdef WIN32
	sscanf(buf, "%s %d ", tmp, &http->status);
	#else
	sscanf(buf, "%s %d ", tmp, &http->status);
	#endif
	if (v_flag)
		fprintf(stdout, "%s: server returned status code %d\n", 
			pname, http->status);

	/* Set SCEP reply type */
	switch (operation) {
		case SCEP_OPERATION_GETCA:
			if (strstr(buf, MIME_GETCA)) {
				http->type = SCEP_MIME_GETCA;
				if (v_flag)
					printf("%s: MIME header: %s\n",
						pname, MIME_GETCA);
			} else if (strstr(buf, MIME_GETCA_RA) ||
				strstr(buf, MIME_GETCA_RA_ENTRUST)) {
				http->type = SCEP_MIME_GETCA_RA;
				if (v_flag)
					printf("%s: MIME header: %s\n",
						pname, MIME_GETCA_RA);
			} else {
				if (v_flag)
					printf("%s: mime_err: %s\n", pname,buf);
				
				goto mime_err;
			}
			break;
		case SCEP_OPERATION_GETNEXTCA:
			if (strstr(buf, MIME_GETNEXTCA)) {
				http->type = SCEP_MIME_GETNEXTCA;
				if (v_flag)
					printf("%s: MIME header: %s\n",
						pname, MIME_GETNEXTCA);
			}else {
				if (v_flag)
					printf("%s: mime_err: %s\n", pname,buf);

				goto mime_err;
			}
			break;
		default:
			if (!strstr(buf, MIME_PKI)) {
				if (v_flag)
					printf("%s: mime_err: %s\n", pname,buf);
				goto mime_err;
			}
			http->type = SCEP_MIME_PKI;
			if (v_flag)
				printf("%s: MIME header: %s\n",pname,MIME_PKI);
			break;
	}

	/* Find payload */
	for (p = buf; *buf; buf++) {
		if (!strncmp(buf, "\n\n", 2) && *(buf + 2)) {
			http->payload = buf + 2;
			break;
		}
		if (!strncmp(buf, "\n\r\n\r", 4) && *(buf + 4)) {
			http->payload = buf + 4;
			break;
		}
		if (!strncmp(buf, "\r\n\r\n", 4) && *(buf + 4)) {
			http->payload = buf + 4;
			break;
		}
	}
	http->bytes = used - (http->payload - p);
	if (http->payload == NULL) {
		/* This is not necessarily error... 
		 * XXXXXXXXXXXXXXXX check */
		fprintf(stderr, "%s: cannot find data from http reply\n",pname);
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
