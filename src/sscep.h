
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

#define NOCRYPT
#include <winsock2.h>
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
#include <openssl/asn1t.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/pkcs7.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
#include <openssl/objects.h>
#include <openssl/ssl.h>
/* Global defines */

#define	VERSION	"0.8.1"

/* SCEP operations */
#define	SCEP_OPERATION_GETCA	1
#define	SCEP_OPERATION_ENROLL	3
#define	SCEP_OPERATION_GETCERT	5
#define	SCEP_OPERATION_GETCRL	7
#define SCEP_OPERATION_GETNEXTCA 15
#define SCEP_OPERATION_GETCAPS  31

/* SCEP MIME headers */
#define MIME_GETCA	"application/x-x509-ca-cert"
#define MIME_GETCA_RA	"application/x-x509-ca-ra-cert"
#define MIME_GETNEXTCA "application/x-x509-next-ca-cert"
#define MIME_GETCAPS	"text/plain"

/* Entrust VPN connector uses different MIME types */
#define MIME_PKI	"application/x-pki-message"
#define MIME_GETCA_RA_ENTRUST	"application/x-x509-ra-ca-certs"

/* SCEP reply types based on MIME headers */
#define	SCEP_MIME_GETCA		1
#define	SCEP_MIME_GETCA_RA	3
#define	SCEP_MIME_PKI		5
#define	SCEP_MIME_GETNEXTCA	7
#define	SCEP_MIME_GETCAPS	15

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

/* SCEP capabilities */
#define SCEP_CAP_AES      0x001
#define SCEP_CAP_3DES     0x002
#define SCEP_CAP_NEXT_CA  0x004
#define SCEP_CAP_POST_PKI 0x008
#define SCEP_CAP_RENEWAL  0x010
#define SCEP_CAP_SHA_1    0x020
#define SCEP_CAP_SHA_224  0x040
#define SCEP_CAP_SHA_256  0x080
#define SCEP_CAP_SHA_384  0x100
#define SCEP_CAP_SHA_512  0x200
#define SCEP_CAP_STA      0x400

#define SCEP_CAPS 11

/* End of Global defines */


/* Global variables */

/* Program name */
extern char *pname;

/* Network timeout */
extern int timeout;

/* Certificates, requests, keys.. */
extern X509 *cacert;
extern X509 *encert;
extern X509 *localcert;
extern X509 *renewal_cert;
extern X509_REQ *request;
extern EVP_PKEY *rsa;
extern EVP_PKEY *renewal_key;
extern X509_CRL *crl;

/* Fingerprint, signing and encryption algorithms */
extern EVP_MD *fp_alg;
extern EVP_MD *sig_alg;
extern EVP_CIPHER *enc_alg;

/* OpenSSL OID handles, defined in sceputils.c */
extern int nid_messageType;
extern int nid_pkiStatus;
extern int nid_failInfo;
extern int nid_senderNonce;
extern int nid_recipientNonce;
extern int nid_transId;
extern int nid_extensionReq;

/* End of Global variables */


/* Structures */

/* GETCertInital data structure */

typedef struct PKCS7_ISSUER_AND_SUBJECT_st {
	X509_NAME *issuer;
	X509_NAME *subject;
} PKCS7_ISSUER_AND_SUBJECT;

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
	PKCS7_ISSUER_AND_SUBJECT *ias_getcertinit;
	PKCS7_ISSUER_AND_SERIAL *ias_getcert;
	PKCS7_ISSUER_AND_SERIAL *ias_getcrl;

	/* Reply */
	PKCS7 *reply_p7;
	char *reply_payload;	
	int reply_len;

	/* Engine */
	ENGINE *e;

};

typedef struct {
	int cap;
	const char * str;
} SCEP_CAP;

/* End of structures */


/* Functions */

/* Print usage information */
void usage(void);

/* Send HTTP message */
int
send_msg(struct http_reply *http, int do_post, char *scep_operation,
		int operation, char *M_char, char *payload, size_t payload_len,
		int p_flag, char *host_name, int host_port, char *dir_name);

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

/* reads the serialnumber from a hex encoded string */
void read_serial(ASN1_INTEGER** target, unsigned char ** source, int source_len);

/* Write CRL */
void write_crl(struct scep *);

/* Write local certificate file */
void write_local_cert(struct scep *);

/* Write other certificate file */
void write_other_cert(struct scep *);

/* Write CA files */
int write_ca_ra(struct http_reply *);

/* Create new SCEP session */
int new_transaction(struct scep *, int operation_flag);

/* Create self-signed certificate */
int new_selfsigned(struct scep *);

/* Get key fingerprint */
char * key_fingerprint(X509_REQ *);

/* PKCS#7 encode message */
int pkcs7_wrap(struct scep *, int enc_base64);

/* PKCS#7 decode message */
int pkcs7_unwrap(struct scep *);

/* Add signed string attribute */
int add_attribute_string(STACK_OF(X509_ATTRIBUTE) *, int, char *);

/* Add signed octet attribute */
int add_attribute_octet(STACK_OF(X509_ATTRIBUTE) *, int, unsigned char *, int);

/* Find signed attributes */
int get_signed_attribute(STACK_OF(X509_ATTRIBUTE) *, int, int, char **);
int get_attribute(STACK_OF(X509_ATTRIBUTE) *, int, ASN1_TYPE **);

/*PKCS#7 decode message without SCEP attribute verification*/
int pkcs7_verify_unwrap(struct scep *s, char * cachainfile );

/* End of Functions */
#endif
