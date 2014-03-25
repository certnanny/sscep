
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


/* Misc. cert/crl manipulation routines */

#include "sscep.h"

/* Open the inner, decrypted PKCS7 and try to write CRL.  */ 
void
write_crl(struct scep *s) {
	PKCS7			*p7;
	STACK_OF(X509_CRL)	*crls;
	X509_CRL		*crl;	
	FILE			*fp;

	/* Get CRL */
	p7 = s->reply_p7;
	crls = p7->d.sign->crl;
	
	/* We expect only one CRL: */
	crl = sk_X509_CRL_value(crls, 0);
	if (crl == NULL) {
		fprintf(stderr, "%s: cannot find CRL in reply\n", pname);
		exit (SCEP_PKISTATUS_FILE);
	}

	/* Write PEM-formatted file: */
	if (!(fp = fopen(w_char, "w"))) {
		fprintf(stderr, "%s: cannot open CRL file for writing\n",
				pname);
		exit (SCEP_PKISTATUS_FILE);
	}
	if (v_flag)
		printf("%s: writing CRL\n", pname);
	if (d_flag)
		PEM_write_X509_CRL(stdout, crl);
	if (PEM_write_X509_CRL(fp, crl) != 1) {
		fprintf(stderr, "%s: error while writing CRL "
			"file\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_FILE);
	}
	printf("%s: CRL written as %s\n", pname, w_char);
	(void)fclose(fp);
}

static int 
compare_subject(X509 * cert)
{
	int rc = X509_NAME_cmp(X509_get_subject_name(cert), X509_REQ_get_subject_name(request));
	
	if (rc)
	{
		/* X509_NAME_cmp should return 0 when X509_get_subject_name()
                 * and X509_REQ_get_subject_name() match. There is a bug
		 * report on that issue (1422).
                 * 
		 * Assume we cannot trust X509_NAME_cmp() and perform a strcmp()
		 * when X509_NAME_cmp returns true (which is in fact false ;-))
		 */
		char cert_buf[1024];
		char req_buf[1024];
		X509_NAME_oneline(X509_get_subject_name(cert), cert_buf, sizeof(cert_buf));
		X509_NAME_oneline(X509_REQ_get_subject_name(request), req_buf, sizeof(req_buf));
		if (v_flag)
			printf (" X509_NAME_cmp() workaround: strcmp request subject (%s) to cert subject (%s)\n", req_buf, cert_buf);
		rc = strcmp (cert_buf, req_buf);
	}

	return rc;
} /* is_same_cn */

/* Open the inner, decrypted PKCS7 and try to write cert.  */ 
void
write_local_cert(struct scep *s) {
	PKCS7			*p7;
	STACK_OF(X509)		*certs;
	X509			*cert = NULL;
	FILE			*fp;
	int			i;

	localcert = NULL;

	/* Get certs */
	p7 = s->reply_p7;
	certs = p7->d.sign->cert;
       
        if (v_flag) {
		printf ("write_local_cert(): found %d cert(s)\n", sk_X509_num(certs));
        }

	/* Find cert */
	for (i = 0; i < sk_X509_num(certs); i++) {
		char buffer[1024];
		cert = sk_X509_value(certs, i);
		if (v_flag) {
			printf("%s: found certificate with\n"
				"  subject: '%s'\n", pname,
				X509_NAME_oneline(X509_get_subject_name(cert),
					buffer, sizeof(buffer)));
			printf("  issuer: %s\n", 
				X509_NAME_oneline(X509_get_issuer_name(cert),
					buffer, sizeof(buffer)));
			printf("  request_subject: '%s'\n", 
				X509_NAME_oneline(X509_REQ_get_subject_name(request),
                                        buffer, sizeof(buffer)));
		}
		/* The subject has to match that of our request */
		if (!compare_subject(cert)) {
			
			if (v_flag)
				printf ("CN's of request and certificate matched!\n");

			/* The subject cannot be the issuer (selfsigned) */
			if (X509_NAME_cmp(X509_get_subject_name(cert),
				X509_get_issuer_name(cert))) {
					localcert = cert;
					break;
			}
		}	
	}
	if (localcert == NULL) {
		fprintf(stderr, "%s: cannot find requested certificate\n",
				pname);
		exit (SCEP_PKISTATUS_FILE);

	}
	/* Write PEM-formatted file: */
	if (!(fp = fopen(l_char, "w"))) {
		fprintf(stderr, "%s: cannot open cert file for writing\n",
				pname);
		exit (SCEP_PKISTATUS_FILE);
	}
	if (v_flag)
		printf("%s: writing cert\n", pname);
	if (d_flag)
		PEM_write_X509(stdout, localcert);
	if (PEM_write_X509(fp, localcert) != 1) {
		fprintf(stderr, "%s: error while writing certificate "
			"file\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_FILE);
	}
	printf("%s: certificate written as %s\n", pname, l_char);
	(void)fclose(fp);
}

/* Open the inner, decrypted PKCS7 and try to write cert.  */ 
void
write_other_cert(struct scep *s) {
	PKCS7			*p7;
	STACK_OF(X509)		*certs;
	X509			*cert = NULL;
	FILE			*fp;
	int			i;

	othercert = NULL;

	/* Get certs */
	p7 = s->reply_p7;
	certs = p7->d.sign->cert;
	
	/* Find cert */
	for (i = 0; i < sk_X509_num(certs); i++) {
		char buffer[1024];

		cert = sk_X509_value(certs, i);
		if (v_flag) {
			printf("%s: found certificate with\n"
				"  subject: %s\n", pname,
				X509_NAME_oneline(X509_get_subject_name(cert),
					buffer, sizeof(buffer)));
			printf("  issuer: %s\n", 
				X509_NAME_oneline(X509_get_issuer_name(cert),
					buffer, sizeof(buffer)));
		}
		/* The serial has to match to requested one */
		if (!ASN1_INTEGER_cmp(X509_get_serialNumber(cert),
				s->ias_getcert->serial)) {
				othercert = cert;	
				break;
		}	
	}
	if (othercert == NULL) {
		fprintf(stderr, "%s: cannot find certificate\n", pname);
		exit (SCEP_PKISTATUS_FILE);

	}
	/* Write PEM-formatted file: */
	if (!(fp = fopen(w_char, "w"))) {
		fprintf(stderr, "%s: cannot open cert file for writing\n",
				pname);
		exit (SCEP_PKISTATUS_FILE);
	}
	if (v_flag)
		printf("%s: writing cert\n", pname);
	if (d_flag)
		PEM_write_X509(stdout, othercert);
	if (PEM_write_X509(fp, othercert) != 1) {
		fprintf(stderr, "%s: error while writing certificate "
			"file\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_FILE);
	}
	printf("%s: certificate written as %s\n", pname, w_char);
	(void)fclose(fp);
}


/*
 * Open the inner, decrypted PKCS7 and try to write CA/RA certificates 
 */
int
write_ca_ra(struct http_reply *s) {
	BIO			*bio;
	PKCS7			*p7;
	STACK_OF(X509)		*certs = NULL;
	X509			*cert = NULL;
	FILE			*fp = NULL;
	int			c, i, index;
        unsigned int		n;
        unsigned char		md[EVP_MAX_MD_SIZE];
	X509_EXTENSION		*ext;

	/* Create read-only memory bio */
	bio = BIO_new_mem_buf(s->payload, s->bytes);
	p7 = d2i_PKCS7_bio(bio, NULL);
	if (p7 == NULL) {
		fprintf(stderr, "%s: error reading PKCS#7 data\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_FILE);
	}
	/* Get certs */
	i = OBJ_obj2nid(p7->type);
	switch (i) {
		case NID_pkcs7_signed:
			certs = p7->d.sign->cert;
			break;
		default:
			printf("%s: wrong PKCS#7 type\n", pname);
			exit (SCEP_PKISTATUS_FILE);
	}
	/* Check  */
	if (certs == NULL) {
		fprintf(stderr, "%s: cannot find certificates\n", pname);
		exit (SCEP_PKISTATUS_FILE);
	} 

	/* Verify the chain
	 * XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
	 */
	/* Find cert */
	for (i = 0; i < sk_X509_num(certs); i++) {
		char buffer[1024];
		char name[1024];

		memset(buffer, 0, 1024);
		memset(name, 0, 1024);
		cert = sk_X509_value(certs, i);

		/* Create name */
		snprintf(name, 1024, "%s-%d", c_char, i);

		/* Read and print certificate information */
		printf("\n%s: found certificate with\n  subject: %s\n", pname,
		X509_NAME_oneline(X509_get_subject_name(cert),
					buffer, sizeof(buffer)));
		printf("  issuer: %s\n", 
			X509_NAME_oneline(X509_get_issuer_name(cert),
					buffer, sizeof(buffer)));
		if (!X509_digest(cert, fp_alg, md, &n)) {
			ERR_print_errors_fp(stderr);
			exit (SCEP_PKISTATUS_FILE);
		}
		/* Print key usage: */
		index = X509_get_ext_by_NID(cert, NID_key_usage, -1);
		if (index < 0) {
			if (v_flag)
				fprintf(stderr, "%s: cannot find key usage\n",
					pname);
			/* exit (SCEP_PKISTATUS_FILE); */
		} else {
			ext = X509_get_ext(cert, index);
			printf("  usage: ");
			X509V3_EXT_print_fp(stdout, ext, 0, 0);
			printf("\n");
		}

		printf("  %s fingerprint: ", OBJ_nid2sn(EVP_MD_type(fp_alg)));
		for (c = 0; c < (int)n; c++) {
			printf("%02X%c",md[c], (c + 1 == (int)n) ?'\n':':');
		}

		/* Write PEM-formatted file: */
		if (!(fp = fopen(name, "w"))) {
			fprintf(stderr, "%s: cannot open cert file for "
				"writing\n", pname);
			exit (SCEP_PKISTATUS_FILE);
		}
		if (v_flag)
			printf("%s: writing cert\n", pname);
		if (d_flag)
			PEM_write_X509(stdout, cert);
		if (PEM_write_X509(fp, cert) != 1) {
			fprintf(stderr, "%s: error while writing certificate "
				"file\n", pname);
			ERR_print_errors_fp(stderr);
			exit (SCEP_PKISTATUS_FILE);
		}
		printf("%s: certificate written as %s\n", pname, name);
	}
	(void)fclose(fp);
	exit (SCEP_PKISTATUS_SUCCESS);
}

/* Read CA cert and optionally, encyption CA cert */

void
read_ca_cert(void) {
	/* Read CA cert file */
	if (!c_flag || !(cafile = fopen(c_char, "r"))) {
		fprintf(stderr, "%s: cannot open CA cert file\n", pname);
		exit (SCEP_PKISTATUS_FILE);
	}
	if (!PEM_read_X509(cafile, &cacert, NULL, NULL)) {
		fprintf(stderr, "%s: error while reading CA cert\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_FILE);
	}
	fclose(cafile);

	/* Read enc CA cert */ 
	if (e_flag) {
		if (!(cafile = fopen(e_char, "r"))) {
			fprintf(stderr, "%s: cannot open enc CA cert file\n",
				pname);
			exit (SCEP_PKISTATUS_FILE);
		}
		if (!PEM_read_X509(cafile, &encert, NULL, NULL)) {
			fprintf(stderr,"%s: error while reading enc CA cert\n",
				pname);
			ERR_print_errors_fp(stderr);
			exit (SCEP_PKISTATUS_FILE);
		}
		fclose(cafile);
	}
}

/* Read local certificate (GetCert and GetCrl) */

void
read_cert(X509** cert, char* filename) {
        FILE *file;
	if (!(file = fopen(filename, "r"))) {
	        fprintf(stderr, "%s: cannot open cert file %s\n", pname, filename);
		exit (SCEP_PKISTATUS_FILE);
	}
	if (!PEM_read_X509(file, cert, NULL, NULL)) {
	        fprintf(stderr, "%s: error while reading cert %s\n", pname, filename);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_FILE);
	}
	fclose(file);
}

/* Read private key */

void
read_key(EVP_PKEY** key, char* filename) {
        FILE *file;
	/* Read private key file */
	if (!(file = fopen(filename, "r"))) {
	        fprintf(stderr, "%s: cannot open private key file %s\n", pname, filename);
		exit (SCEP_PKISTATUS_FILE);
	}
	if (!PEM_read_PrivateKey(file, key, NULL, NULL)) {
	        fprintf(stderr, "%s: error while reading private key %s\n", pname, filename);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_FILE);
	}
	fclose(file);
}

/* Read PKCS#10 request */

void
read_request(void) {
	/* Read certificate request file */
	if (!r_flag || !(reqfile = fopen(r_char, "r"))) {
		fprintf(stderr, "%s: cannot open certificate request\n", pname);
		exit (SCEP_PKISTATUS_FILE);
	}
	if (!PEM_read_X509_REQ(reqfile, &request, NULL, NULL)) {
		fprintf(stderr, "%s: error while reading request file\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_FILE);
	}
	fclose(reqfile);
}

