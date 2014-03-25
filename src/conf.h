
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


/* Network timeout */
#define	TIMEOUT		120

/* Polling interval seconds */
#define	POLL_TIME	300

/* Max polling seconds */
#define	MAX_POLL_TIME	28800

/* Max polling count */
#define	MAX_POLL_COUNT	256

/* CA identifier */
#define	CA_IDENTIFIER	"CAIdentifier"

/* Self signed certificate expiration */
#define SELFSIGNED_EXPIRE_DAYS	365

/* Transaction id for GetCert and GetCrl methods */
#define TRANS_ID_GETCERT	"SSCEP transactionId"

