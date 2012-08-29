
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/* Macros */

#define i2d_pkcs7_issuer_and_subject_bio(bp, ias) \
	ASN1_i2d_bio(i2d_pkcs7_issuer_and_subject, bp, (unsigned char *)ias)
#define i2d_PKCS7_ISSUER_AND_SERIAL_bio(bp, ias)  \
	ASN1_i2d_bio(i2d_PKCS7_ISSUER_AND_SERIAL, bp, (unsigned char *)ias)

/* Routines */
int i2d_pkcs7_issuer_and_subject(pkcs7_issuer_and_subject *, unsigned char **);
pkcs7_issuer_and_subject *
d2i_pkcs7_issuer_and_subject(pkcs7_issuer_and_subject **, unsigned char **,
	long length);
pkcs7_issuer_and_subject *pkcs7_issuer_and_subject_new(void);
void pkcs7_issuer_and_subject_free(pkcs7_issuer_and_subject *);


