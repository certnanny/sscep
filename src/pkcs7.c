/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/* PKCS#7 routines */

#include "sscep.h"
#include "ias.h"

/*
 * Wrap data in PKCS#7 envelopes and base64-encode the result.
 * Data is PKCS#10 request in PKCSReq, or pkcs7_issuer_and_subject
 * structure in GetCertInitial and PKCS7_ISSUER_AND_SERIAL in
 * GetCert and GETCrl.
 */
int pkcs7_wrap(struct scep *s) {
	BIO			*databio = NULL;
	BIO			*encbio = NULL;
	BIO			*pkcs7bio = NULL;
	BIO			*memorybio = NULL;
	BIO			*outbio = NULL;
	BIO			*base64bio = NULL;
	unsigned char		*buffer = NULL;
	int			rc, len = 0;
	STACK_OF(X509)		*recipients;
	PKCS7			*p7enc;
	PKCS7_SIGNER_INFO	*si;
	STACK_OF(X509_ATTRIBUTE) *attributes;
	X509			*signercert = NULL;
	EVP_PKEY		*signerkey = NULL;

	/* Create a new sender nonce for all messages 
	 * XXXXXXXXXXXXXX should it be per transaction? */
	s->sender_nonce_len = 16;
	s->sender_nonce = (unsigned char *)malloc(s->sender_nonce_len); 
	RAND_bytes(s->sender_nonce, s->sender_nonce_len);

	/* Prepare data payload */
	switch(s->request_type) {
		case SCEP_REQUEST_PKCSREQ:
			/*
			 * Set printable message type
			 * We set this later as an autheticated attribute
			 * "messageType".
			 */
			s->request_type_str = SCEP_REQUEST_PKCSREQ_STR;

			/* Signer cert */
			signercert = s->signercert;
			signerkey = s->signerkey;

			/* Create inner PKCS#7  */
			if (v_flag)
				printf("%s: creating inner PKCS#7\n", pname);

			/* Read request in memory bio */
			databio = BIO_new(BIO_s_mem());
			if ((rc = i2d_X509_REQ_bio(databio, request)) <= 0) {
				fprintf(stderr, "%s: error writing "
					"certificate request in bio\n", pname);
				ERR_print_errors_fp(stderr);
				exit (SCEP_PKISTATUS_P7);
			}
			BIO_flush(databio);
			BIO_set_flags(databio, BIO_FLAGS_MEM_RDONLY); 
			break;

		case SCEP_REQUEST_GETCERTINIT:

			/* Set printable message type */
			s->request_type_str = SCEP_REQUEST_GETCERTINIT_STR;

			/* Signer cert */
			signercert = s->signercert;
			signerkey = s->signerkey;

			/* Create inner PKCS#7  */
			if (v_flag)
				printf("%s: creating inner PKCS#7\n", pname);

			/* Read data in memory bio */
			databio = BIO_new(BIO_s_mem());
			if ((rc = i2d_pkcs7_issuer_and_subject_bio(databio,
						s->ias_getcertinit)) <= 0) {
				fprintf(stderr, "%s: error writing "
					"GetCertInitial data in bio\n", pname);
				ERR_print_errors_fp(stderr);
				exit (SCEP_PKISTATUS_P7);
			}
			BIO_flush(databio);
			BIO_set_flags(databio, BIO_FLAGS_MEM_RDONLY); 
			break;

		case SCEP_REQUEST_GETCERT:
			/* Set printable message type */
			s->request_type_str = SCEP_REQUEST_GETCERT_STR;

			/* Signer cert */
			signercert = localcert;
			signerkey = rsa;

			/* Read data in memory bio */
			databio = BIO_new(BIO_s_mem());
			if ((rc = i2d_PKCS7_ISSUER_AND_SERIAL_bio(databio,
						s->ias_getcert)) <= 0) {
				fprintf(stderr, "%s: error writing "
					"GetCert data in bio\n", pname);
				ERR_print_errors_fp(stderr);
				exit (SCEP_PKISTATUS_P7);
			}
			BIO_flush(databio);
			BIO_set_flags(databio, BIO_FLAGS_MEM_RDONLY); 
			break;

		case SCEP_REQUEST_GETCRL:
			/* Set printable message type */
			s->request_type_str = SCEP_REQUEST_GETCRL_STR;

			/* Signer cert */
			signercert = localcert;
			signerkey = rsa;

			/* Read data in memory bio */
			databio = BIO_new(BIO_s_mem());
			if ((rc = i2d_PKCS7_ISSUER_AND_SERIAL_bio(databio,
						s->ias_getcrl)) <= 0) {
				fprintf(stderr, "%s: error writing "
					"GetCert data in bio\n", pname);
				ERR_print_errors_fp(stderr);
				exit (SCEP_PKISTATUS_P7);
			}
			BIO_flush(databio);
			BIO_set_flags(databio, BIO_FLAGS_MEM_RDONLY); 
			break;
	}
	/* Below this is the common code for all request_type */

	/* Read in the payload */
	s->request_len = BIO_get_mem_data(databio, &s->request_payload);
	if (v_flag)
		printf("%s: data payload size: %d bytes\n", pname,
				s->request_len);
	BIO_free(databio);

	/* Create encryption certificate stack */
	if ((recipients = sk_X509_new(NULL)) == NULL) {
		fprintf(stderr, "%s: error creating "
					"certificate stack\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	/* Use different CA cert for encryption if requested */
	if (e_flag) {
		if (sk_X509_push(recipients, encert) <= 0) {
			fprintf(stderr, "%s: error adding recipient encryption "
					"certificate\n", pname);
			ERR_print_errors_fp(stderr);
			exit (SCEP_PKISTATUS_P7);
		}
	/* Use same CA cert also for encryption */
	} else {
		if (sk_X509_push(recipients, cacert) <= 0) {
			fprintf(stderr, "%s: error adding recipient encryption "
					"certificate\n", pname);
			ERR_print_errors_fp(stderr);
			exit (SCEP_PKISTATUS_P7);
		}
	}

	/* Create BIO for encryption  */
	if ((encbio = BIO_new_mem_buf(s->request_payload,
				s->request_len)) == NULL) {
		fprintf(stderr, "%s: error creating data " "bio\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	} 

	/* Encrypt */
	if (!(p7enc = PKCS7_encrypt(recipients, encbio,
					enc_alg, PKCS7_BINARY))) {
		fprintf(stderr, "%s: request payload encrypt failed\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	if (v_flag)
		printf("%s: successfully encrypted payload\n", pname);

	/* Write encrypted data */
	memorybio = BIO_new(BIO_s_mem());
	if (i2d_PKCS7_bio(memorybio, p7enc) <= 0) {
		fprintf(stderr, "%s: error writing encrypted data\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	BIO_flush(memorybio);
	BIO_set_flags(memorybio, BIO_FLAGS_MEM_RDONLY); 
	len = BIO_get_mem_data(memorybio, &buffer);
	if (v_flag)
		printf("%s: envelope size: %d bytes\n", pname, len);
	if (d_flag) {
		printf("%s: printing PEM fomatted PKCS#7\n", pname);
		PEM_write_PKCS7(stdout, p7enc);
	}
	BIO_free(memorybio); 

	/* Create outer PKCS#7  */
	if (v_flag)
		printf("%s: creating outer PKCS#7\n", pname);
	s->request_p7 = PKCS7_new();
	if (s->request_p7 == NULL) {
		fprintf(stderr, "%s: failed creating PKCS#7 for signing\n",
					pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	if (!PKCS7_set_type(s->request_p7, NID_pkcs7_signed)) {
		fprintf(stderr, "%s: failed setting PKCS#7 type\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}

	/* Add signer certificate  and signature */
	PKCS7_add_certificate(s->request_p7, signercert);
	if ((si = PKCS7_add_signature(s->request_p7,
				signercert, signerkey, sig_alg)) == NULL) {
		fprintf(stderr, "%s: error adding PKCS#7 signature\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	if (v_flag)
		printf("%s: signature added successfully\n", pname);

	/* Set signed attributes */
	if (v_flag)
		printf("%s: adding signed attributes\n", pname);
	attributes = sk_X509_ATTRIBUTE_new_null();	
	add_attribute_string(attributes, nid_transId, s->transaction_id);
	add_attribute_string(attributes, nid_messageType, s->request_type_str);
	add_attribute_octet(attributes, nid_senderNonce, s->sender_nonce,
			s->sender_nonce_len);
	PKCS7_set_signed_attributes(si, attributes);
	
	/* Add contentType */
	if (!PKCS7_add_signed_attribute(si, NID_pkcs9_contentType,
			V_ASN1_OBJECT, OBJ_nid2obj(NID_pkcs7_data))) {
		fprintf(stderr, "%s: error adding NID_pkcs9_contentType\n",
					pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}

	/* Create new content */
	if (!PKCS7_content_new(s->request_p7, NID_pkcs7_data)) {
		fprintf(stderr, "%s: failed setting PKCS#7 content type\n",
					pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}

	/* Write data  */
	pkcs7bio = PKCS7_dataInit(s->request_p7, NULL);
	if (pkcs7bio == NULL) {
		fprintf(stderr, "%s: error opening bio for writing PKCS#7 "
			"data\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	if (len != BIO_write(pkcs7bio, buffer, len)) {
		fprintf(stderr, "%s: error writing PKCS#7 data\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	if (v_flag)
		printf("%s: PKCS#7 data written successfully\n", pname);

	/* Finalize PKCS#7  */
	if (!PKCS7_dataFinal(s->request_p7, pkcs7bio)) {
		fprintf(stderr, "%s: error finalizing outer PKCS#7\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	if (d_flag) {
		printf("%s: printing PEM fomatted PKCS#7\n", pname);
		PEM_write_PKCS7(stdout, s->request_p7);
	}

	/* base64-encode the data */
	if (v_flag)
		printf("%s: applying base64 encoding\n",pname);

	/* Create base64 filtering bio */
	memorybio = BIO_new(BIO_s_mem());
	base64bio = BIO_new(BIO_f_base64());
	outbio = BIO_push(base64bio, memorybio);

	/* Copy PKCS#7 */
	i2d_PKCS7_bio(outbio, s->request_p7);
	BIO_flush(outbio);
	BIO_set_flags(memorybio, BIO_FLAGS_MEM_RDONLY);
	s->request_len = BIO_get_mem_data(memorybio, &s->request_payload);
	if (v_flag)
		printf("%s: base64 encoded payload size: %d bytes\n",
				pname, s->request_len);
	BIO_free(outbio);

	return (0);
}

/*
 * Unwrap PKCS#7 data and decrypt if necessary
 */
int pkcs7_unwrap(struct scep *s) {
	BIO				*memorybio;
	BIO				*outbio;
	BIO				*pkcs7bio;
	int				i, len, bytes, used;
	STACK_OF(PKCS7_SIGNER_INFO)	*sk;
	PKCS7				*p7enc;
	PKCS7_SIGNER_INFO		*si;
	STACK_OF(X509_ATTRIBUTE)	*attribs;
	char				*p;
	unsigned char			buffer[1024];
	X509				*recipientcert;
	EVP_PKEY			*recipientkey;

	/* Create new memory BIO for outer PKCS#7 */
	memorybio = BIO_new(BIO_s_mem());

	/* Read in data */
	if (v_flag)
		printf("%s: reading outer PKCS#7\n",pname);
	if ((len = BIO_write(memorybio, s->reply_payload, s->reply_len)) <= 0) {
		fprintf(stderr, "%s: error reading PKCS#7 data\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	if (v_flag)
		printf("%s: PKCS#7 payload size: %d bytes\n", pname, len);
	BIO_set_flags(memorybio, BIO_FLAGS_MEM_RDONLY); 
	s->reply_p7 = d2i_PKCS7_bio(memorybio, NULL);
	if (d_flag) {
		printf("%s: printing PEM fomatted PKCS#7\n", pname);
		PEM_write_PKCS7(stdout, s->reply_p7);
	}

	 /* Make sure this is a signed PKCS#7 */
        if (!PKCS7_type_is_signed(s->reply_p7)) {
		fprintf(stderr, "%s: PKCS#7 is not signed!\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
        }

	/* Create BIO for content data */
	pkcs7bio = PKCS7_dataInit(s->reply_p7, NULL);
	if (pkcs7bio == NULL) {
		fprintf(stderr, "%s: cannot get PKCS#7 data\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}

	/* Copy enveloped data from PKCS#7 */
	outbio = BIO_new(BIO_s_mem());
	used = 0;
	for (;;) {
		bytes = BIO_read(pkcs7bio, buffer, sizeof(buffer));
		used += bytes;
		if (bytes <= 0) break;
		BIO_write(outbio, buffer, bytes);
	}
	BIO_flush(outbio);
	if (v_flag)
		printf("%s: PKCS#7 contains %d bytes of enveloped data\n",
			pname, used);

	/* Get signer */
	sk = PKCS7_get_signer_info(s->reply_p7);
	if (sk == NULL) {
		fprintf(stderr, "%s: cannot get signer info!\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}

	/* Verify signature */
	if (v_flag)
		printf("%s: verifying signature\n", pname);
	si = sk_PKCS7_SIGNER_INFO_value(sk, 0);
	if (PKCS7_signatureVerify(pkcs7bio, s->reply_p7, si, cacert) <= 0) {
		fprintf(stderr, "%s: error verifying signature\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	if (v_flag)
		printf("%s: signature ok\n", pname);

	/* Get signed attributes */
	if (v_flag)
		printf("%s: finding signed attributes\n", pname);
	attribs = PKCS7_get_signed_attributes(si);
	if (attribs == NULL) {
		fprintf(stderr, "%s: no attributes found\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}

	/* Transaction id */
	if ((get_signed_attribute(attribs, nid_transId,
			V_ASN1_PRINTABLESTRING, &p)) == 1) {
		fprintf(stderr, "%s: cannot find transId\n", pname);
		exit (SCEP_PKISTATUS_P7);
	}
	if (v_flag)
		printf("%s: reply transaction id: %s\n", pname, p);
	if (strncmp(s->transaction_id, p, strlen(p))) {
		fprintf(stderr, "%s: transaction id mismatch\n", pname);
		exit (SCEP_PKISTATUS_P7);
	}
	/* Message type, should be of type CertRep */
	if ((i = get_signed_attribute(attribs, nid_messageType,
			V_ASN1_PRINTABLESTRING, &p)) == 1) {
		fprintf(stderr, "%s: cannot find messageType\n", pname);
		exit (SCEP_PKISTATUS_P7);
	}
	if (atoi(p) != 3) {
		fprintf(stderr, "%s: wrong message type in reply\n", pname);
		exit (SCEP_PKISTATUS_P7);
	}
	if (v_flag)
		printf("%s: reply message type is good\n", pname);

	/* Sender and recipient nonces: */
	if ((i = get_signed_attribute(attribs, nid_senderNonce,
			V_ASN1_OCTET_STRING, &p)) == 1) {
		if (v_flag)
			fprintf(stderr, "%s: cannot find senderNonce\n", pname);
		/* Some implementations don't put in on reply */
		/* XXXXXXXXXXXXXXXXXXXXXXXXXXXXX
		exit (SCEP_PKISTATUS_P7); */
	}
	s->reply_sender_nonce = p;
	if (v_flag) {
		printf("%s: senderNonce in reply: ", pname);
		for (i = 0; i < 16; i++) {
			printf("%02X", s->reply_sender_nonce[i]);
		}
		printf("\n");
	}
	if (( i = get_signed_attribute(attribs, nid_recipientNonce,
			V_ASN1_OCTET_STRING, &p)) == 1) {
		fprintf(stderr, "%s: cannot find recipientNonce\n", pname);
		exit (SCEP_PKISTATUS_P7);
	}
	s->reply_recipient_nonce = p;
	if (v_flag) {
		printf("%s: recipientNonce in reply: ", pname);
		for (i = 0; i < 16; i++) {
			printf("%02X", s->reply_recipient_nonce[i]);
		}
		printf("\n");
	}
	/*
	 * Compare recipient nonce to original sender nonce 
	 * The draft says nothing about this, but it makes sense to me..
	 * XXXXXXXXXXXXXX check
	 */
	for (i = 0; i < 16; i++) {
		if (s->sender_nonce[i] != s->reply_recipient_nonce[i]) {
			if (v_flag)
				fprintf(stderr, "%s: corrupted nonce "
					"received\n", pname);
			/* Instead of exit, break out */
			break;
		}
	}
	/* Get pkiStatus */
	if ((i = get_signed_attribute(attribs, nid_pkiStatus,
			V_ASN1_PRINTABLESTRING, &p)) == 1) {
		fprintf(stderr, "%s: cannot find pkiStatus\n", pname);
		/* This is a mandatory attribute.. */
		exit (SCEP_PKISTATUS_P7);
	}
	switch (atoi(p)) {
		case SCEP_PKISTATUS_SUCCESS:
			printf("%s: pkistatus: SUCCESS\n",pname);
			s->pki_status = SCEP_PKISTATUS_SUCCESS;
			break;
		case SCEP_PKISTATUS_FAILURE:
			printf("%s: pkistatus: FAILURE\n",pname);
			s->pki_status = SCEP_PKISTATUS_FAILURE;
			break;
		case SCEP_PKISTATUS_PENDING:
			printf("%s: pkistatus: PENDING\n",pname);
			s->pki_status = SCEP_PKISTATUS_PENDING;
			break;
		default:
			fprintf(stderr, "%s: wrong pkistatus in reply\n",pname);
			exit (SCEP_PKISTATUS_P7);
	}

	/* Get failInfo */
	if (s->pki_status == SCEP_PKISTATUS_FAILURE) {
		if ((i = get_signed_attribute(attribs, nid_failInfo,
			V_ASN1_PRINTABLESTRING, &p)) == 1) {
				fprintf(stderr, "%s: cannot find failInfo\n",
						pname);
				exit (SCEP_PKISTATUS_P7);
		}
		switch (atoi(p)) {
			case SCEP_FAILINFO_BADALG:
				s->fail_info = SCEP_FAILINFO_BADALG;
				printf("%s: reason: %s\n", pname,
					SCEP_FAILINFO_BADALG_STR);
				break;
			case SCEP_FAILINFO_BADMSGCHK:
				s->fail_info = SCEP_FAILINFO_BADMSGCHK;
				printf("%s: reason: %s\n", pname,
					SCEP_FAILINFO_BADMSGCHK_STR);
				break;
			case SCEP_FAILINFO_BADREQ:
				s->fail_info = SCEP_FAILINFO_BADREQ;
				printf("%s: reason: %s\n", pname,
					SCEP_FAILINFO_BADREQ_STR);
				break;
			case SCEP_FAILINFO_BADTIME:
				s->fail_info = SCEP_FAILINFO_BADTIME;
				printf("%s: reason: %s\n", pname,
					SCEP_FAILINFO_BADTIME_STR);
				break;
			case SCEP_FAILINFO_BADCERTID:		
				s->fail_info = SCEP_FAILINFO_BADCERTID;
				printf("%s: reason: %s\n", pname,
					SCEP_FAILINFO_BADCERTID_STR);
				break;
			default:
				fprintf(stderr, "%s: wrong failInfo in "							"reply\n",pname);
				exit (SCEP_PKISTATUS_P7);
		}
	}
	/* If FAILURE or PENDING, we can return */
	if (s->pki_status != SCEP_PKISTATUS_SUCCESS) {
		/* There shouldn't be any more data... */
		if (v_flag && (used != 0)) {
			fprintf(stderr, "%s: illegal size of payload\n", pname);
		}
		return (0);
	}
	/* We got success and expect data */
	if (used == 0) {
		fprintf(stderr, "%s: illegal size of payload\n", pname);
		exit (SCEP_PKISTATUS_P7);
	}

	/* Decrypt the inner PKCS#7 */
	if ((s->request_type == SCEP_REQUEST_PKCSREQ) ||
	    (s->request_type == SCEP_REQUEST_GETCERTINIT)) {
		recipientcert = s->signercert;
		recipientkey = s->signerkey;
	}
	else {
		recipientcert = localcert;
		recipientkey = rsa;
	}
	if (v_flag)
		printf("%s: reading inner PKCS#7\n",pname);
	p7enc = d2i_PKCS7_bio(outbio, NULL);
	if (p7enc == NULL) {
		fprintf(stderr, "%s: cannot read inner PKCS#7\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	if (d_flag) {
		printf("%s: printing PEM fomatted PKCS#7\n", pname);
		PEM_write_PKCS7(stdout, p7enc);
	}

	/* Decrypt the data  */
	outbio = BIO_new(BIO_s_mem());
	if (v_flag)
		printf("%s: decrypting inner PKCS#7\n",pname);
	if (PKCS7_decrypt(p7enc, recipientkey, recipientcert, outbio, 0) == 0) {
		fprintf(stderr, "%s: error decrypting inner PKCS#7\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	BIO_flush(outbio);

	/* Write decrypted data */
	s->reply_len = BIO_get_mem_data(outbio, &s->reply_payload);
	if (v_flag)
		printf("%s: PKCS#7 payload size: %d bytes\n", pname,
			s->reply_len);
	BIO_set_flags(outbio, BIO_FLAGS_MEM_RDONLY); 
	s->reply_p7 = d2i_PKCS7_bio(outbio, NULL);

	return (0);

}

/* Add signed attributes */
int
add_attribute_string(STACK_OF(X509_ATTRIBUTE) *attrs, int nid, char *buffer) {
	ASN1_STRING     *asn1_string = NULL;
	X509_ATTRIBUTE  *x509_a;
	int		c;

	if (v_flag)
		printf("%s: adding string attribute %s\n", pname,
			OBJ_nid2sn(nid));

	asn1_string = ASN1_STRING_new();
	if ((c = ASN1_STRING_set(asn1_string, buffer, strlen(buffer))) <= 0) {
		fprintf(stderr, "%s: error adding data to ASN.1 string\n",
			pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	x509_a = X509_ATTRIBUTE_create(nid, V_ASN1_PRINTABLESTRING,
		asn1_string);
	sk_X509_ATTRIBUTE_push(attrs, x509_a);
	
	return (0);

}
int
add_attribute_octet(STACK_OF(X509_ATTRIBUTE) *attrs, int nid, char *buffer,
		int len) {
	ASN1_STRING     *asn1_string = NULL;
	X509_ATTRIBUTE  *x509_a;
	int		c;

	if (v_flag)
		printf("%s: adding octet attribute %s\n", pname,
			OBJ_nid2sn(nid));

	asn1_string = ASN1_STRING_new();
	if ((c = ASN1_STRING_set(asn1_string, buffer, len)) <= 0) {
		fprintf(stderr, "%s: error adding data to ASN.1 string\n",
			pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	x509_a = X509_ATTRIBUTE_create(nid, V_ASN1_OCTET_STRING,
		asn1_string);
	sk_X509_ATTRIBUTE_push(attrs, x509_a);
	
	return (0);

}

/* Find signed attributes */
int
get_signed_attribute(STACK_OF(X509_ATTRIBUTE) *attribs, int nid,
		int type, char **buffer) {
	int		rc; 
	ASN1_TYPE	*asn1_type;
	unsigned int	len;

	/* Find attribute */
	rc = get_attribute(attribs, nid, &asn1_type);
	if (rc == 1) {
		if (v_flag)
			fprintf(stderr, "%s: error finding attribute\n",pname);	
		return (1);
	}
	if (ASN1_TYPE_get(asn1_type) != type) {
		fprintf(stderr, "%s: wrong ASN.1 type\n",pname);	
		exit (SCEP_PKISTATUS_P7);
	}

	/* Copy data */
	len = ASN1_STRING_length(asn1_type->value.asn1_string);
	if (len <= 0) {
		return (1);
	} else if (v_flag)
		printf("%s: allocating %d bytes for attribute\n", pname, len);
	if (type == V_ASN1_PRINTABLESTRING) {
		*buffer = (unsigned char *)malloc(len + 1);
	} else {
		*buffer = (unsigned char *)malloc(len);
	}
	if (*buffer == NULL) {
		fprintf(stderr, "%s: cannot malloc space for attribute\n",
			pname);	
		exit (SCEP_PKISTATUS_P7);
	}
	memcpy(*buffer, ASN1_STRING_data(asn1_type->value.asn1_string), len);

	/* Add null terminator if it's a PrintableString */
	if (type == V_ASN1_PRINTABLESTRING) {
		(*buffer)[len] = 0;
		len++;
	}

	return (0);
} 
int
get_attribute(STACK_OF(X509_ATTRIBUTE) *attribs, int required_nid,
				ASN1_TYPE **asn1_type) {
	int		i;
	ASN1_OBJECT	*asn1_obj = NULL;
	X509_ATTRIBUTE	*x509_attrib = NULL;

	if (v_flag)
		printf("%s: finding attribute %s\n", pname,
			OBJ_nid2sn(required_nid));
	*asn1_type = NULL;
	asn1_obj = OBJ_nid2obj(required_nid);
	if (asn1_obj == NULL) {
		fprintf(stderr, "%s: error creating ASN.1 object\n", pname);	
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_P7);
	}
	/* Find attribute */
	for (i = 0; i < sk_X509_ATTRIBUTE_num(attribs); i++) {
		x509_attrib = sk_X509_ATTRIBUTE_value(attribs, i);
		if (OBJ_cmp(x509_attrib->object, asn1_obj) == 0) {
			if ((x509_attrib->value.set) &&
			  (sk_ASN1_TYPE_num(x509_attrib->value.set) != 0)) {
				if (*asn1_type != NULL) {
					fprintf(stderr, "%s: no value found",
							pname);
					exit (SCEP_PKISTATUS_P7);
				}
			*asn1_type =
				sk_ASN1_TYPE_value(x509_attrib->value.set, 0);
			}
		}
	}

	if (*asn1_type == NULL)
		return (1);
	return (0);
} 
