#include "engine.h"

ENGINE *scep_engine_init(ENGINE *e) {
	

		ENGINE_load_builtin_engines();
		ENGINE_load_dynamic();
		//if its not dynamic, try to load it directly. If OpenSSL has it already we are good to go!
		if(strcmp(g_char, "dynamic") != 0)
		{
			e = ENGINE_by_id(g_char);
			if ((e==NULL) && v_flag){
				printf("%s: Engine %s could not be loaded. Trying to load dynamically...\n", pname, g_char);
			}
		}

		if(e == NULL)
		{
			e = scep_engine_load_dynamic(e);
		}

		//define this engine as a default for all our crypto operations. This way OpenSSL automatically chooses the right functions
		if(ENGINE_set_default(e, ENGINE_METHOD_ALL) == 0) {
				fprintf(stderr, "%s: Error loading on setting defaults\n", pname);
				sscep_engine_report_error();
				exit (SCEP_PKISTATUS_ERROR);
		} else if(v_flag)
			printf("%s: Engine %s made default for all operations\n", pname, g_char);

		//we need a functional reference and as such need to initialize
		if(ENGINE_init(e) == 0) {
			fprintf(stderr, "%s: Engine Init did not work\n", pname);
			sscep_engine_report_error();
			exit (SCEP_PKISTATUS_ERROR);
		} else if(v_flag)
			printf("%s: Engine %s initialized\n", pname, g_char);


		//TODO: remove capi specific part!
		if(v_flag) {
			// set debug level
			if(!ENGINE_ctrl(e, (ENGINE_CMD_BASE + 2), 2, NULL, NULL)) {
				fprintf(stderr, "%s: Could not set debug level to %i", pname, 2);
				sscep_engine_report_error();
				exit (SCEP_PKISTATUS_ERROR);
			}
			// set debug file (log)
			if(!ENGINE_ctrl(e, (ENGINE_CMD_BASE + 3), 0, "capi.log", NULL)) {
				fprintf(stderr, "%s: Could not set debug file to %s", pname, "capi.log");
				sscep_engine_report_error();
				exit (SCEP_PKISTATUS_ERROR);
			}
		}


		return e;
}

ENGINE *scep_engine_load_dynamic(ENGINE *e) {
	//it seems OpenSSL did not already have it. In this case we will try to load it dynamically
	e = ENGINE_by_id("dynamic");

	//if we can't even load the dynamic engine, something is seriously wrong. We can't go on from here!
	if(e == NULL) {
		fprintf(stderr, "%s: Engine dynamic could not be loaded, Error message\n", pname);
		sscep_engine_report_error();
		exit (SCEP_PKISTATUS_ERROR);
	} else if(v_flag)
		printf("%s: Engine dynamic was loaded\n", pname);

	//To load dynamically we have to tell openssl where to find it.
	if(scep_conf->engine->dynamic_path) {
		if(ENGINE_ctrl_cmd_string(e, "SO_PATH", scep_conf->engine->dynamic_path, 0) == 0) {
			fprintf(stderr, "%s: Loading %s did not succeed\n", pname, g_char);
			sscep_engine_report_error();
			exit (SCEP_PKISTATUS_ERROR);
		} else if (v_flag)
			printf("%s: %s was found.\n", pname, g_char);
	}

	//engine will be added to the list of available engines. Should be done for complete import.
	if(ENGINE_ctrl_cmd_string(e, "LIST_ADD", "1", 0) == 0) {
		fprintf(stderr, "%s: Executing LIST_ADD did not succeed:\n", pname);
		sscep_engine_report_error();
		exit (SCEP_PKISTATUS_ERROR);
	} else if(v_flag)
		printf("%s: Added %s to list of engines.\n", pname, g_char);

	/*if(!ENGINE_ctrl(e, (ENGINE_CMD_BASE + 12), 0, (void*)"REQUEST", NULL)) {
	} else if(v_flag)
		printf("Altered storename to %s\n", "REQUEST");*/

	//Finally we load the engine.
	if(ENGINE_ctrl_cmd_string(e, "LOAD", NULL, 0) == 0) {
		fprintf(stderr, "%s: Executing LOAD did not succeed:\n", pname);
		sscep_engine_report_error();
		exit (SCEP_PKISTATUS_ERROR);
	} else if(v_flag)
		printf("%s: Loading engine %s succeeded\n", pname, g_char);

	//all these functions were only needed if we loaded dynamically. Otherwise we could just skip this step.

	return e;
}

//idea from: http://blog.burghardt.pl/2010/03/ncipher-hsm-with-openssl/
void sscep_engine_read_key(EVP_PKEY **key, char *id, ENGINE *e) {
	BIO *bio;
	*key = ENGINE_load_private_key(e, id, NULL, NULL);
	if(*key == 0) {
		printf("Could not load private key!\n");
		exit(SCEP_PKISTATUS_FILE);
	} else if(d_flag) {
		bio = BIO_new_fp(stdout, BIO_NOCLOSE);
		//printf("%s: Key id: %i for string %s\n", pname, EVP_PKEY_id(*key), id);
		EVP_PKEY_print_private(bio, *key, 0, NULL);
		BIO_flush(bio);
		BIO_free_all(bio);
	}
}

void sscep_engine_read_key_old(EVP_PKEY **key, char *id, ENGINE *e) {
	if(!strncmp(scep_conf->engine->engine_id, "capi", 4)) {
		sscep_engine_read_key_capi(key, id, e, "MY");
	} else {
		sscep_engine_read_key(key, id, e);
	}
	
}

void sscep_engine_read_key_new(EVP_PKEY **key, char *id, ENGINE *e) {
	if(!strncmp(scep_conf->engine->engine_id, "capi", 4)) {
		sscep_engine_read_key_capi(key, id, e, scep_conf->engine->new_key_location);
	} else {
		sscep_engine_read_key(key, id, e);
	}
}

void sscep_engine_read_key_capi(EVP_PKEY **key, char *id, ENGINE *e, char *storename) {
	static ENGINE* me;
	if(me && !e)
		e = me;
	if(e)
		me = e;
	if(!storename)
		storename = "MY";
	if(!ENGINE_ctrl(e, CAPI_CMD_STORE_NAME, 0, (void*)storename, NULL)) {
		fprintf(stderr, "%s: Executing CAPI_CMD_STORE_NAME did not succeed\n", pname);
		sscep_engine_report_error();
		exit(SCEP_PKISTATUS_ERROR);
	}
	sscep_engine_read_key(key, id, e);
}

void sscep_engine_report_error() {
	ERR_load_crypto_strings();
	ERR_print_errors_fp(stderr);
	ERR_free_strings();
}