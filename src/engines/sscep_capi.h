#include <stdio.h>
#include <string.h>
#include <openssl/conf.h>


#define SCEP_CONFIGURATION_ENGINE_CAPI_STORELOCATION	"storelocation"
#define SCEP_CONFIGURATION_ENGINE_CAPI_NEWKEYLOCATION	"new_key_location"

__declspec(dllexport) void GetCapiOptions(void);

struct capi_options_st {
	char *new_key_location;
	int storelocation;
};

typedef capi_options_st CAPI_OPTIONS;

typedef struct capi_functions_st {
	CAPI_OPTIONS (*getConfig)(void);
} CAPI_FUNCTIONS;