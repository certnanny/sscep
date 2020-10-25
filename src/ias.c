
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


/*
 * Routines for pkcs7_issuer_and_subject data type needed when
 * sending GETCertInitial requests.
 */

#include "sscep.h"
#include "ias.h"

ASN1_SEQUENCE(PKCS7_ISSUER_AND_SUBJECT) = {
        ASN1_SIMPLE(PKCS7_ISSUER_AND_SUBJECT, issuer, X509_NAME),
        ASN1_SIMPLE(PKCS7_ISSUER_AND_SUBJECT, subject, X509_NAME),
} ASN1_SEQUENCE_END(PKCS7_ISSUER_AND_SUBJECT)

IMPLEMENT_ASN1_FUNCTIONS(PKCS7_ISSUER_AND_SUBJECT);

