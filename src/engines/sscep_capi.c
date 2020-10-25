#include "sscep_capi.h"

static CAPI_FUNCTIONS capi_functions = {
	sscep_engine_capi_loadConfig,
};

static struct capi_options_st *capi_options;

char *pname = "sscep_capi.dll";
int v_flag = 0;

__declspec(dllexport) void sscep_engine_special_init(int verbose) {
	v_flag = verbose;
	capi_options = malloc(sizeof(capi_options_st));
}

__declspec(dllexport) CAPI_OPTIONS sscep_engine_capi_loadConfig(CONF *conf, char *section) {
	char *var;

	if(var = NCONF_get_string(conf, section, SCEP_CONFIGURATION_ENGINE_CAPI_NEWKEYLOCATION)) {
		if(v_flag)
			printf("%s: Location of the new key will be in %s\n", pname, var);
		capi_options->new_key_location = var;
	} else {
		if(v_flag)
			printf("%s: No new key location was provided, using default \"REQUEST\"\n", pname);
		capi_options->new_key_location = "REQUEST";
	}

	if(var = NCONF_get_string(conf, section, SCEP_CONFIGURATION_ENGINE_CAPI_STORELOCATION)) {
		if(v_flag)
			printf("%s: The store used will be %s\n", pname, var);
		if(!strncmp(var, "LOCAL_MACHINE", 13)) {
			capi_options->storelocation = 1;
		} else if(!strncmp(var, "CURRENT_USER", 12)) {
			capi_options->storelocation = 0;
		} else {
			printf("%s: Provided storename unknown (%s). Will use the engines default.\n", pname, var);
			capi_options->storelocation = 0;
		}
	} else {
		if(v_flag)
			printf("%s: No storename was provided. Will use the engines default.\n", pname);
		capi_options->new_key_location = 0;
	}
}

__declspec(dllexport) void sscep_engine_capi_free() {
	free(capi_options);
}