
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */
#ifndef SSCEP_H
#define SSCEP_H

#include "conf.h"
#include "cmd.h"

#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <setjmp.h>
#include "getopt.h"
#include "fileutils_capi.h"
#include "configuration.h"
#include "engine.h"

#ifdef WIN32

#include <winsock.h>
#include <io.h>

#ifdef _DEBUG
#include <crtdbg.h>
#endif

#define snprintf _snprintf
#define close _close
#define sleep(t_num) Sleep((t_num)*1000)
#pragma comment(lib, "crypt32.lib")

#else

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>

#endif

#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/buffer.h>
#include <openssl/asn1.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/objects.h>
#include <openssl/asn1_mac.h>
#include <openssl/ssl.h>
/* Global defines */

#define	VERSION	"0.2"

/* SCEP operations */
int operation_flag;
#define	SCEP_OPERATION_GETCA	1
#define	SCEP_OPERATION_ENROLL	3
#define	SCEP_OPERATION_GETCERT	5
#define	SCEP_OPERATION_GETCRL	7
#define SCEP_OPERATION_GETNEXTCA 15

/* SCEP MIME headers */
#define MIME_GETCA	"application/x-x509-ca-cert"
#define MIME_GETCA_RA	"application/x-x509-ca-ra-cert"
#define MIME_GETNEXTCA "application/x-x509-next-ca-cert"

/* Entrust VPN connector uses different MIME types */
#define MIME_PKI	"x-pki-message"
#define MIME_GETCA_RA_ENTRUST	"application/x-x509-ra-ca-certs"

/* SCEP reply types based on MIME headers */
#define	SCEP_MIME_GETCA		1
#define	SCEP_MIME_GETCA_RA	3
#define	SCEP_MIME_PKI		5
#define	SCEP_MIME_GETNEXTCA	7

/* SCEP request types */
#define	SCEP_REQUEST_NONE		0
#define	SCEP_REQUEST_PKCSREQ		19
#define	SCEP_REQUEST_PKCSREQ_STR	"19"
#define	SCEP_REQUEST_GETCERTINIT	20
#define	SCEP_REQUEST_GETCERTINIT_STR	"20"
#define	SCEP_REQUEST_GETCERT		21
#define	SCEP_REQUEST_GETCERT_STR	"21"
#define	SCEP_REQUEST_GETCRL		22
#define	SCEP_REQUEST_GETCRL_STR		"22"

/* SCEP reply types */
#define	SCEP_REPLY_NONE		0
#define	SCEP_REPLY_CERTREP	3
#define	SCEP_REPLY_CERTREP_STR	"3"

/* SCEP pkiStatus values (also used as SSCEP return values) */
#define SCEP_PKISTATUS_SUCCESS		0
#define SCEP_PKISTATUS_FAILURE		2
#define SCEP_PKISTATUS_PENDING		3

/* SSCEP return values (not in SCEP draft) */
#define SCEP_PKISTATUS_ERROR		1 /* General error */
#define SCEP_PKISTATUS_BADALG		70 /* BADALG failInfo */
#define SCEP_PKISTATUS_BADMSGCHK	71 /* BADMSGCHK failInfo */
#define SCEP_PKISTATUS_BADREQ		72 /* BADREQ failInfo */
#define SCEP_PKISTATUS_BADTIME		73 /* BADTIME failInfo */
#define SCEP_PKISTATUS_BADCERTID	74 /* BADCERTID failInfo */
#define SCEP_PKISTATUS_TIMEOUT		89 /* Network timeout */
#define SCEP_PKISTATUS_SS		91 /* Error generating selfsigned */
#define SCEP_PKISTATUS_FILE		93 /* Error in file handling */
#define SCEP_PKISTATUS_NET		95 /* Network sending message */
#define SCEP_PKISTATUS_P7		97 /* Error in pkcs7 routines */
#define SCEP_PKISTATUS_UNSET		99 /* Unset pkiStatus */

/* SCEP failInfo values */
#define SCEP_FAILINFO_BADALG		0
#define SCEP_FAILINFO_BADALG_STR	\
	"Unrecognized or unsupported algorithm ident"
#define SCEP_FAILINFO_BADMSGCHK		1
#define SCEP_FAILINFO_BADMSGCHK_STR	\
	"Integrity check failed"
#define SCEP_FAILINFO_BADREQ		2
#define SCEP_FAILINFO_BADREQ_STR	\
	"Transaction not permitted or supported" 
#define SCEP_FAILINFO_BADTIME		3
#define SCEP_FAILINFO_BADTIME_STR	\
	"Message time field was not sufficiently close to the system time"
#define SCEP_FAILINFO_BADCERTID		4
#define SCEP_FAILINFO_BADCERTID_STR 	\
	"No certificate could be identified matching"

//define encoding for capi engine support
#define MY_ENCODING_TYPE  (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)

/* End of Global defines */


/* Global variables */

/* Program name */
char *pname;

/* Network timeout */
int timeout;

/* Certificates, requests, keys.. */
X509 *cacert;
X509 *encert;
X509 *localcert;
X509 *othercert;
X509 *renewal_cert;
X509_REQ *request;
EVP_PKEY *rsa;
EVP_PKEY *renewal_key;
X509_CRL *crl;
FILE *cafile;
FILE *reqfile;
FILE *otherfile;
FILE *crlfile;

/* Fingerprint, signing and encryption algorithms */
EVP_MD *fp_alg;
EVP_MD *sig_alg;
EVP_CIPHER *enc_alg;

/* OpenSSL OID handles */
int nid_messageType;
int nid_pkiStatus;
int nid_failInfo;
int nid_senderNonce;
int nid_recipientNonce;
int nid_transId;
int nid_extensionReq;

/* Global pkistatus */
int pkistatus;

/* End of Global variables */


/* Structures */

/* GETCertInital data structure */

typedef struct {
	X509_NAME *issuer;
	X509_NAME *subject;
} pkcs7_issuer_and_subject;

/* HTTP reply structure */
struct http_reply {

	/* SCEP reply type */
	int type;

	/* Status */
	int status;

	/* Payload */
	char *payload;

	/* Payload size */
	int bytes;
};

/* SCEP transaction structure */
struct scep {

	/* SCEP message types */
	int request_type;
	char *request_type_str;
	int reply_type;
	char *reply_type_str;

	/* SCEP message status */
	int pki_status;
	char *pki_status_str;
	int fail_info;
	char *fail_info_str;

	/* SCEP transaction attributes */
	char *transaction_id;
	unsigned char *sender_nonce;
	int sender_nonce_len;
	unsigned char *reply_recipient_nonce;
	unsigned char *reply_sender_nonce;
	int recipient_nonce_len;

	/* Certificates */
	X509 *signercert;
	EVP_PKEY *signerkey;

	EVP_PKEY *pkey;

	/* Request */
	PKCS7 *request_p7;
	unsigned char *request_payload;
	int request_len;
	pkcs7_issuer_and_subject *ias_getcertinit;
	PKCS7_ISSUER_AND_SERIAL *ias_getcert;
	PKCS7_ISSUER_AND_SERIAL *ias_getcrl;

	/* Reply */
	PKCS7 *reply_p7;
	unsigned char *reply_payload;	
	int reply_len;

	/* Engine */
	ENGINE *e;

};
/* End of structures */


/* Functions */

/* Print usage information */
void usage(void);

/* Send HTTP message */
int send_msg (struct http_reply *, char *, char *, int, int);

/* Catch SIGALRM */
void catchalarm (int);

/* Get config file parameter */
char *get_string (char *);

/* Report memory error */
void error_memory(void);

/* Initialize config file */
void init_config(FILE *);

/* Initialize SCEP layer */
int init_scep(void);

/* Read RSA private key file */
void read_key(EVP_PKEY** key, char* filename);

/* Read RSA private key using hwcrhk */
void read_key_Engine(EVP_PKEY** key, char* filename, ENGINE *e);

/* Read CA certificate file */
void read_ca_cert(void);

/* Read local certificate file */
void read_cert(X509** cert, char* filename);

/* Read certificate from engine */
/*void read_cert_Engine(X509** cert, char* id, ENGINE *e, char* filename);*/

/* Read certificate request and private key */
void read_request(void);

/* Write CRL */
void write_crl(struct scep *);

/* Write local certificate file */
void write_local_cert(struct scep *);

/* Write other certificate file */
void write_other_cert(struct scep *);

/* Write CA files */
int write_ca_ra(struct http_reply *);

/* Create new SCEP session */
int new_transaction(struct scep *);

/* Create self-signed certificate */
int new_selfsigned(struct scep *);

/* Get key fingerprint */
char * key_fingerprint(X509_REQ *);

/* PKCS#7 encode message */
int pkcs7_wrap(struct scep *);

/* PKCS#7 decode message */
int pkcs7_unwrap(struct scep *);

/* Add signed string attribute */
int add_attribute_string(STACK_OF(X509_ATTRIBUTE) *, int, char *);

/* Add signed octet attribute */
int add_attribute_octet(STACK_OF(X509_ATTRIBUTE) *, int, char *, int);

/* Find signed attributes */
int get_signed_attribute(STACK_OF(X509_ATTRIBUTE) *, int, int, char **);
int get_attribute(STACK_OF(X509_ATTRIBUTE) *, int, ASN1_TYPE **);

/*PKCS#7 decode message without SCEP attribute verification*/
int pkcs7_verify_unwrap(struct scep *s, char * cachainfile );

/* URL-endcode */
char *url_encode (char *, size_t);

/* End of Functions */
#endif
