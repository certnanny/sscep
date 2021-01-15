
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


/* Misc. cert/crl manipulation routines */

#if !defined(__APPLE__)
#include <malloc.h>
#endif
#include "sscep.h"

X509 *cacert;
X509 *encert;
X509 *localcert;
X509 *renewal_cert;
X509_REQ *request;
EVP_PKEY *rsa;
EVP_PKEY *renewal_key;
X509_CRL *crl;

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
#ifdef WIN32
	if ((fopen_s(&fp, w_char, "w")))
#else
	if (!(fp = fopen(w_char, "w")))
#endif
	{
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
	char buffer[1024];
	int rc = X509_NAME_cmp(X509_get_subject_name(cert), X509_REQ_get_subject_name(request));
	if(d_flag) {
		fprintf(stderr, "Subject of the returned certificate: %s\n", X509_NAME_oneline(X509_get_subject_name(cert), NULL, 0));
		fprintf(stderr, "Subject of the request: %s\n",
				X509_NAME_oneline(X509_REQ_get_subject_name(request), buffer, sizeof(buffer))
			);
	}
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
		} else {
			fprintf(stderr, "%s: Subject of our request does not match that of the returned Certificate!\n", pname);
			//exit (SCEP_PKISTATUS_FILE);
		}
		
		/* The subject cannot be the issuer (selfsigned) */
		if (X509_NAME_cmp(X509_get_subject_name(cert),
			X509_get_issuer_name(cert))) {
				localcert = cert;
				break;
		}
	}
	if (localcert == NULL) {
		fprintf(stderr, "%s: cannot find requested certificate\n",
				pname);
		exit (SCEP_PKISTATUS_FILE);

	}
	/* Write PEM-formatted file: */
#ifdef WIN32
	if ((fopen_s(&fp, l_char, "w")))
#else
	if (!(fp = fopen(l_char, "w")))
#endif
	{
		fprintf(stderr, "%s: cannot open cert file for writing\n",
				pname);
		exit (SCEP_PKISTATUS_FILE);
	}
	if (v_flag)
		printf("%s: certificate written as %s\n", pname, l_char);
	if (d_flag)
		PEM_write_X509(stdout, localcert);
	if (PEM_write_X509(fp, localcert) != 1) {
		fprintf(stderr, "%s: error while writing certificate "
			"file\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_FILE);
	}
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
	X509 *othercert = NULL;

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
#ifdef WIN32
	if ((fopen_s(&fp, w_char, "w")))
#else
	if (!(fp = fopen(w_char, "w")))
#endif
	{
		fprintf(stderr, "%s: cannot open cert file for writing\n",
				pname);
		exit (SCEP_PKISTATUS_FILE);
	}
	if (v_flag)
		printf("%s: certificate written as %s\n", pname, w_char);
	if (d_flag)
		PEM_write_X509(stdout, othercert);
	if (PEM_write_X509(fp, othercert) != 1) {
		fprintf(stderr, "%s: error while writing certificate "
			"file\n", pname);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_FILE);
	}
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
		if (v_flag){
		printf("\n%s: found certificate with\n  subject: %s\n", pname,
		X509_NAME_oneline(X509_get_subject_name(cert),
					buffer, sizeof(buffer)));
		}
		if (v_flag)
		printf("  issuer: %s\n", 
			X509_NAME_oneline(X509_get_issuer_name(cert),
					buffer, sizeof(buffer)));
		if (!X509_digest(cert, fp_alg, md, &n)) {
			ERR_print_errors_fp(stderr);
			exit (SCEP_PKISTATUS_FILE);
		}
		/* Print basic constraints: */
		index = X509_get_ext_by_NID(cert, NID_basic_constraints, -1);
		if (index < 0) {
			if (v_flag)
				printf("  basic constraints: (not included)\n");
		} else {
			ext = X509_get_ext(cert, index);
			if (v_flag){
				printf("  basic constraints: ");
				X509V3_EXT_print_fp(stdout, ext, 0, 0);
				printf("\n");
			}
		}
		/* Print key usage: */
		index = X509_get_ext_by_NID(cert, NID_key_usage, -1);
		if (index < 0) {
			if (v_flag)
				printf("  usage: (not included)\n");
		} else {
			ext = X509_get_ext(cert, index);
			if (v_flag){
				printf("  usage: ");
				X509V3_EXT_print_fp(stdout, ext, 0, 0);
				printf("\n");
			}
		}
		if (v_flag){
			printf("  %s fingerprint: ", OBJ_nid2sn(EVP_MD_type(fp_alg)));
			for (c = 0; c < (int)n; c++) {
				printf("%02X%c",md[c], (c + 1 == (int)n) ?'\n':':');
			}
		}

		/* Write PEM-formatted file: */
#ifdef WIN32
		if ((fopen_s(&fp, name, "w")))
#else
		if (!(fp = fopen(name, "w")))
#endif
		{
			fprintf(stderr, "%s: cannot open cert file for "
				"writing\n", pname);
			exit (SCEP_PKISTATUS_FILE);
		}
		if (v_flag)
			printf("%s: certificate written as %s\n", pname, name);
		if (d_flag)
			PEM_write_X509(stdout, cert);
		if (PEM_write_X509(fp, cert) != 1) {
			fprintf(stderr, "%s: error while writing certificate "
				"file\n", pname);
			ERR_print_errors_fp(stderr);
			exit (SCEP_PKISTATUS_FILE);
		}

		fclose(fp);
	}

	PKCS7_free(p7);
	BIO_free(bio);
	exit (SCEP_PKISTATUS_SUCCESS);
}

/* Read local certificate (GetCert and GetCrl) */

X509 *
read_cert(const char *filename)
{
	FILE *file;
	X509 *res;

	if (
#ifdef WIN32
		(fopen_s(&file, filename, "r"))
#else
		!(file = fopen(filename, "r"))
#endif
		)
	{
		return NULL;
	}

	if (!(res = PEM_read_X509(file, NULL, NULL, NULL)))
		ERR_print_errors_fp(stderr);

	fclose(file);

	return res;
}

/* Read CA cert and optionally, encyption CA cert */

void
guess_ca_certs(const char* filename, X509 **sigc, X509 **encc)
{
	int ccnt, i, j;
	X509 *cert[20];

	ccnt = 0;
	/* read all certificates */
	while (ccnt < 20) {
		char name[1024];

		snprintf(name, sizeof(name)-1, "%s-%d", filename, ccnt);
		if (!(cert[ccnt] = read_cert(name)))
			break;

		ccnt++;
	}

	/* this is either NULL or the first certificate */
	*sigc = *encc = cert[0];

	for (i = 0; i < ccnt; i++) {
		X509_NAME *myname = X509_get_subject_name(cert[i]);
		int is_issuer = 0;

		/* the right CA is the final-one, either leaf or not */
		for (j = 0; j < ccnt; j++) {
			X509_NAME *issuer = X509_get_issuer_name(cert[j]);
			if (!X509_NAME_cmp(myname, issuer)) {
				is_issuer = 1;
				break;
			}
		}

		if (!is_issuer) {
			/* X509_get_key_usage(cert[i]) is not in older openssl */
			ASN1_BIT_STRING *usage = X509_get_ext_d2i(cert[i], NID_key_usage, NULL, NULL);
			if (usage && (usage->length > 0)) {
				if (usage->data[0] & KU_DIGITAL_SIGNATURE)
					*sigc = cert[i];
				if (usage->data[0] & KU_KEY_ENCIPHERMENT)
					*encc = cert[i];
			} else {
				/* no usability constraints */
				*sigc = *encc = cert[i];
			}
		}
	}

	/* release those we don't use */
	for (i = 0; i < ccnt; i++) {
		if (cert[i] != *sigc && cert[i] != *encc)
			X509_free(cert[i]);
	}

	if (v_flag) {
		char buffer[1024];

		if (*sigc)
			printf("%s: using RA certificate: %s\n", pname,
				X509_NAME_oneline(X509_get_subject_name(*sigc),
						buffer, sizeof(buffer)));
		if (*encc)
			printf("%s: using RA encryption certificate: %s\n", pname,
				X509_NAME_oneline(X509_get_subject_name(*encc),
						buffer, sizeof(buffer)));
	}

}

/*
void read_cert_Engine(X509** cert, char* id, ENGINE *e, char* filename)
{
	BIO *bio, *b64;
	PCCERT_CONTEXT ctx = NULL;
	int ret;
	HCERTSTORE store;
	DWORD cbSize;
	LPTSTR pszName;
	LPSTR str;
	FILE *certfile;
	
	store = CertOpenSystemStore(0, L"MY");
	
	ctx = CertFindCertificateInStore(store, MY_ENCODING_TYPE, 0, CERT_FIND_SUBJECT_STR, (LPCSTR) id, NULL);
	if(!ctx) {
		while(ctx = CertEnumCertificatesInStore(store, ctx))
		{
			cbSize = CertGetNameString(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
			pszName = (LPTSTR)malloc(cbSize * sizeof(TCHAR));
			CertGetNameString(ctx, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, pszName, cbSize);
			cbSize = WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK | WC_DEFAULTCHAR, (LPCWSTR) pszName, -1, NULL, 0, NULL, NULL);
			str = (LPSTR)malloc(cbSize * sizeof(LPSTR));
			WideCharToMultiByte(CP_ACP, WC_NO_BEST_FIT_CHARS | WC_COMPOSITECHECK | WC_DEFAULTCHAR, (LPCWSTR) pszName, -1, str, cbSize, NULL, NULL);
			if(strstr(str, id)) {
				ret = 0;
				break;
			} else {
				ret = 127;
			}
		}
	}
	if(!ctx || ret != 0)
	{
		fprintf(stderr, "%s: cannot find Certificate with subject %s in store\n", pname, id);
		exit(SCEP_PKISTATUS_FILE);
	}

	certfile = fopen(filename, "w");
	fputs("-----BEGIN CERTIFICATE-----\n", certfile);
	fclose(certfile);

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new_file(filename, "a");
	bio = BIO_push(b64, bio);
	ret = BIO_write(bio, ctx->pbCertEncoded, ctx->cbCertEncoded);
	ret = BIO_flush(bio);
	BIO_free_all(bio);

	certfile = fopen(filename, "a");
	fputs("-----END CERTIFICATE-----", certfile);
	fclose(certfile);

	read_cert(cert, filename);
}*/


/* Read private key */

EVP_PKEY *
read_key(char* filename)
{
	FILE *file;
	EVP_PKEY *res;
	/* Read private key file */
#ifdef WIN32
	if ((fopen_s(&file, filename, "r")))
#else
	if (!(file = fopen(filename, "r")))
#endif
	{
	    fprintf(stderr, "%s: cannot open private key file %s\n", pname, filename);
		exit (SCEP_PKISTATUS_FILE);
	}
	if (!(res = PEM_read_PrivateKey(file, NULL, NULL, NULL))) {
	        fprintf(stderr, "%s: error while reading private key %s\n", pname, filename);
		ERR_print_errors_fp(stderr);
		exit (SCEP_PKISTATUS_FILE);
	}
	fclose(file);
	return res;
}

/* Read PKCS#10 request */

void
read_request(void) {
	FILE *reqfile;

	/* Read certificate request file */
	if (!r_flag || 
#ifdef WIN32
		(fopen_s(&reqfile, r_char, "r")))
#else
		!(reqfile = fopen(r_char, "r")))
#endif
	{
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

