/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/* Misc. SCEP routines */

#include "sscep.h"
#include "ias.h"

/* OpenSSL OID handles */
int nid_messageType;
int nid_pkiStatus;
int nid_failInfo;
int nid_senderNonce;
int nid_recipientNonce;
int nid_transId;
int nid_extensionReq;

/*
 * Initialize a SCEP transaction
 */
int new_transaction(struct scep *s, int operation_flag) {

	/* Set the whole struct as 0 */
	memset(s, 0, sizeof(*s));

	/* Set request and reply type */
	s->request_type = SCEP_REQUEST_NONE;
	s->request_type_str = NULL;
	s->reply_type = SCEP_REPLY_NONE;
	s->reply_type_str = NULL;
	s->pki_status = SCEP_PKISTATUS_UNSET;
	s->pki_status_str = NULL;
	s->fail_info_str = NULL;

	/* Set other variables */
	s->ias_getcertinit = PKCS7_ISSUER_AND_SUBJECT_new();
	s->ias_getcert = PKCS7_ISSUER_AND_SERIAL_new();
	s->ias_getcrl = PKCS7_ISSUER_AND_SERIAL_new();

	/* Create transaction id */
	if (operation_flag == SCEP_OPERATION_ENROLL)
		s->transaction_id = key_fingerprint(request);
	else
		s->transaction_id = TRANS_ID_GETCERT;
	if (v_flag) {
		printf("%s: transaction id: %s\n", pname, s->transaction_id);
	}
	return (0);
}

/*
 * Create self signed certificate based on request subject.
 * Set also subjectAltName extension if found from request.
 */
int new_selfsigned(struct scep *s) {
	X509			 *cert;
	X509_NAME		 *subject;
	ASN1_INTEGER		 *serial;
/* No extensions in selfsigned
	X509_EXTENSION		 *subject_altname;
	STACK_OF(X509_EXTENSION) *req_extensions;
	int			 subject_altname_pos;
*/

	/* Extract public value of the local key from request */
	if (!(s->pkey = X509_REQ_get_pubkey(request))) {
		fprintf(stderr, "%s: error getting public key from request\n",
			pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}

	/* Get subject, issuer and extensions */
	if (!(subject = X509_REQ_get_subject_name(request))) {
		fprintf(stderr, "%s: error getting subject\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}

/* Don't generate v3 extensions in selfsigned.. */
#if 0
	if (!(req_extensions = X509_REQ_get_extensions(request))) {
		fprintf(stderr, "%s: error getting X509v3 extensions\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}
	/* Only supported extension is subjectAltName */
	subject_altname_pos = X509v3_get_ext_by_NID(req_extensions,
		OBJ_sn2nid("subjectAltName"), -1);
	subject_altname = X509v3_get_ext(req_extensions, subject_altname_pos);
#endif

	/* Create new certificate */
	if (!(cert = X509_new())) {
		fprintf(stderr, "%s: error creating X509 certificate\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}
	/* Set version (X509v3) */
	if (X509_set_version(cert, 2L) != 1) {
		fprintf(stderr, "%s: error setting cert version\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}
	/* Get serial no from transaction id */
	read_serial(&serial, (unsigned char **) &s->transaction_id, 32);
	if (!serial) {
		fprintf(stderr, "%s: error converting serial\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}
	if (X509_set_serialNumber(cert, serial) != 1) { 
		fprintf(stderr, "%s: error setting serial\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}
	/* Set subject */
	if (X509_set_subject_name(cert, subject) != 1) {
		fprintf(stderr, "%s: error setting subject\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}
	/* Set issuer (it's really the same as subject */
	if (X509_set_issuer_name(cert, subject) != 1) {
		fprintf(stderr, "%s: error setting issuer\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}
	/* Set public key */
	if (X509_set_pubkey(cert, s->pkey) != 1) {
		fprintf(stderr, "%s: error setting public key", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}
	/* Set duration */
	if (!(X509_gmtime_adj(X509_getm_notBefore(cert), 0))) {
		fprintf(stderr, "%s: error setting begin time", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}
	if (!(X509_gmtime_adj(X509_getm_notAfter(cert),
			SELFSIGNED_EXPIRE_DAYS * 24 * 60))) {
		fprintf(stderr, "%s: error setting end time", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}
/* Don't generate v3 extensions in selfsigned.. */
#if 0
	/* Add subjectAltName */
	if (subject_altname && !X509_add_ext(cert, subject_altname, -1)) {
		fprintf(stderr, "%s: error setting subjectAltName", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}
#endif
	/* Sign certificate */
	if (!(X509_sign(cert, rsa, sig_alg))) {
		fprintf(stderr, "%s: error signing certificate", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_SS);
	}

	/* Copy the pointer and return */
	s->signercert = cert;
	s->signerkey = rsa;
	return (0);
}

/*
 * Initialize SCEP
 */
int init_scep() {
	/* Create OpenSSL NIDs */
	nid_messageType = OBJ_create("2.16.840.1.113733.1.9.2", "messageType",
		"messageType");
	if (nid_messageType == 0) {
		goto err;
	}
	nid_pkiStatus = OBJ_create("2.16.840.1.113733.1.9.3", "pkiStatus",
		"pkiStatus");
	if (nid_pkiStatus == 0) {
		goto err;
	}
	nid_failInfo = OBJ_create("2.16.840.1.113733.1.9.4", "failInfo",
		"failInfo");
	if (nid_failInfo == 0) {
		goto err;
	}
	nid_senderNonce = OBJ_create("2.16.840.1.113733.1.9.5", "senderNonce",
		"senderNonce");
	if (nid_senderNonce == 0) {
		goto err;
	}
	nid_recipientNonce = OBJ_create("2.16.840.1.113733.1.9.6",
				"recipientNonce", "recipientNonce");
	if (nid_recipientNonce == 0) {
		goto err;
	}
	nid_transId = OBJ_create("2.16.840.1.113733.1.9.7", "transId",
		"transId");
	if (nid_transId == 0) {
		goto err;
	}
	nid_extensionReq = OBJ_create("2.16.840.1.113733.1.9.8",
				"extensionReq", "extensionReq");
	if (nid_extensionReq == 0) {
		goto err;
	}
	return (0);

err:
	fprintf(stderr, "%s: cannot create OID\n", pname);
	return (1);

}

/*
 * Calculate transaction id.
 * Return pointer to ascii presentation of the hash.
 */
char *
key_fingerprint(X509_REQ *req) {
	char		*ret, *str;
	unsigned char	*data, md[MD5_DIGEST_LENGTH];
	int		c, len;
	BIO		*bio;
	EVP_MD_CTX	*mdctx;
	
	/* Assign space for ASCII presentation of the digest */
	str = (char *)malloc(2 * MD5_DIGEST_LENGTH + 1);
	ret = str;

	/* Create new memory bio for reading the public key */
	bio = BIO_new(BIO_s_mem());
	i2d_PUBKEY_bio(bio, X509_REQ_get_pubkey(req));
	len = BIO_get_mem_data(bio, &data);

	/* Calculate MD5 hash: */
	mdctx = EVP_MD_CTX_new();
	EVP_DigestInit_ex(mdctx, EVP_md5(), NULL);
	EVP_DigestUpdate(mdctx, data, len);
	EVP_DigestFinal_ex(mdctx, md, NULL);
	EVP_MD_CTX_free(mdctx);

	/* Copy as ASCII string and return: */
	for (c = 0; c < MD5_DIGEST_LENGTH; c++, str += 2) {
		sprintf((char *)str, "%02X", md[c]);

	}
	*(str) = '\0';
	return(ret);
}

/**
 * c2i_ASN1_INTERNAL is not supported anymore since openssl 1.1.x. The only way to
 * still get the ASN1_INTEGER is by using d2i_ASN1_INTERNAL instead. However, this requires
 * the string to start with two additional octets. One for the type (integer: 0x02) and another
 * one representing the data length (source_length).
 */
void read_serial(ASN1_INTEGER** target, unsigned char ** source, int source_len) {
    const int buffer_len = source_len + 2;
    const unsigned char * buffer = malloc(sizeof(unsigned char)*buffer_len);

    snprintf((char *) buffer, buffer_len, "%c%c%s", 2, source_len, *source);

    *target = d2i_ASN1_INTEGER(NULL, &buffer, buffer_len);
}