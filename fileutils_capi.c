#include "sscep.h"



void capi_read_key_Engine(EVP_PKEY** key, char* id, ENGINE *e, char* storename);



void capi_read_key_Engine(EVP_PKEY** key, char* id, ENGINE *e, char* storename) {
	if(!ENGINE_ctrl(e, CAPI_CMD_STORE_NAME, 0, (void*)storename, NULL)) {
		ERR_load_CRYPTO_strings();
		fprintf(stderr, "Executing CAPI_CMD_STORE_NAME did not succeed: %s\n", ERR_error_string(ERR_peek_last_error(), NULL));
		ERR_free_strings();
		exit(SCEP_PKISTATUS_ERROR);
	}
	//loading the key
	*key = ENGINE_load_private_key(e, id, NULL, NULL);
	if(!key) {
		printf("%s: Could not load key %s from storename %s\n", pname, id, storename);
		exit(SCEP_PKISTATUS_FILE);
	}

	//ENGINE_ctrl(e, CAPI_CMD_STORE_NAME, 0, (void*)"MY", NULL);
}
