
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

ASN1_SEQUENCE(pkcs7_issuer_and_subject) = {
        ASN1_SIMPLE(pkcs7_issuer_and_subject, subject, X509_NAME),
        ASN1_SIMPLE(pkcs7_issuer_and_subject, issuer, X509_NAME),
} ASN1_SEQUENCE_END(pkcs7_issuer_and_subject)

IMPLEMENT_ASN1_FUNCTIONS(pkcs7_issuer_and_subject);
IMPLEMENT_ASN1_PRINT_FUNCTION(pkcs7_issuer_and_subject);

IMPLEMENT_ASN1_PRINT_FUNCTION(PKCS7_ISSUER_AND_SERIAL);