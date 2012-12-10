/*
 * This file reads from an OpenSSL configuration file.
 * A sample file is attached to the program
 * 
 *
 *
 */
#ifndef CONFIGURATION_H
#define CONFIGURATION_H

#include <stdio.h>
#include <stdlib.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include "sscep.h"

/*
 * Definition of sections for configuration
 * Base Section is [sscep], all base options are defined here
 * The operation sections are all named [operation], e.g. [enroll]
 * The engine section is dynamically defined via the "engine"-param in [sscep]
 */
#define SCEP_CONFIGURATION_SECTION						"sscep"
#define SCEP_CONFIGURATION_SECTION_ENGINE_TEMPLATE		"sscep_engine_%s"
#define SCEP_CONFIGURATION_SECTION_GETCA				"sscep_getca"
#define SCEP_CONFIGURATION_SECTION_GETNEXTCA			"sscep_getnextca"
#define SCEP_CONFIGURATION_SECTION_ENROLL				"sscep_enroll"
#define SCEP_CONFIGURATION_SECTION_GETCERT				"sscep_getcert"
#define SCEP_CONFIGURATION_SECTION_GETCRL				"sscep_getcrl"


/*
 * The param "engine" defines the name of the section
 * of the engine configuration.
 * All SCEP_CONFIGURATION_ENGINE_* params are expected to be
 * in this section
 * All other parameters are located in their corresponding
 * operation section.
 * Note: Parameters can be defined in multiple sections under
 * the same name since only one operation section will be loaded
 * at a time.
 */
#define SCEP_CONFIGURATION_PARAM_ENGINE					"engine"
#define SCEP_CONFIGURATION_ENGINE_ID					"engine_id"
#define SCEP_CONFIGURATION_ENGINE_CAPI_STORELOCATION	"storelocation"
#define SCEP_CONFIGURATION_ENGINE_CAPI_NEWKEYLOCATION	"new_key_location"
#define SCEP_CONFIGURATION_ENGINE_JKSENGINE_KEYSTOREPASS "KeyStorePass"
#define SCEP_CONFIGURATION_ENGINE_JKSENGINE_PROVIDER	"KeyStoreProvider"
#define SCEP_CONFIGURATION_ENGINE_JKSENGINE_JCONNPATH	"JavaConnectorPath"
#define SCEP_CONFIGURATION_ENGINE_JKSENGINE_JAVAPATH	"JavaPath"
#define SCEP_CONFIGURATION_ENGINE_PKCS11_PIN			"PIN"
#define SCEP_CONFIGURATION_ENGINE_DYNPATH				"dynamic_path"
#define SCEP_CONFIGURATION_ENGINE_MODULEPATH			"MODULE_PATH"
#define SCEP_CONFIGURATION_PARAM_CACERTFILE				"CACertFile"
#define SCEP_CONFIGURATION_PARAM_NEXTCACERTFILE			"NextCACertFile"
#define SCEP_CONFIGURATION_PARAM_CERTROOTCHAINFILE		"ChainRootCACertFile"
#define SCEP_CONFIGURATION_PARAM_CAIDENTIFIER			"CAIdentifier"
#define SCEP_CONFIGURATION_PARAM_CERTREQFILE			"CertReqFile"
#define SCEP_CONFIGURATION_PARAM_DEBUG					"Debug"
#define SCEP_CONFIGURATION_PARAM_ENCCERTFILE			"EncCertFile"
#define SCEP_CONFIGURATION_PARAM_ENCALGORITHM			"EncAlgorithm"
#define SCEP_CONFIGURATION_PARAM_FINGERPRINT			"FingerPrint"
#define SCEP_CONFIGURATION_PARAM_GETCERTFILE			"GetCertFile"
#define SCEP_CONFIGURATION_PARAM_GETCRLFILE				"GetCrlFile"
#define SCEP_CONFIGURATION_PARAM_GETCERTSERIAL			"GetCertSerial"
#define SCEP_CONFIGURATION_PARAM_LOCALCERTFILE			"LocalCertFile"
#define SCEP_CONFIGURATION_PARAM_SIGNCERTFILE			"SignCertFile"
#define SCEP_CONFIGURATION_PARAM_MAXPOLLCOUNT			"MaxPollCount"
#define SCEP_CONFIGURATION_PARAM_MAXPOLLTIME			"MaxPollTime"
#define SCEP_CONFIGURATION_PARAM_PRIVATEKEYFILE			"PrivateKeyFile"
#define SCEP_CONFIGURATION_PARAM_SIGNKEYFILE			"SignKeyFile"
#define SCEP_CONFIGURATION_PARAM_SELFSIGNEDFILE			"SelfSignedFile"
#define SCEP_CONFIGURATION_PARAM_SIGALGORITHM			"SigAlgorithm"
#define SCEP_CONFIGURATION_PARAM_PROXY					"Proxy"
#define SCEP_CONFIGURATION_PARAM_POLLINTERVAL			"PollInterval"
#define SCEP_CONFIGURATION_PARAM_URL					"URL"
#define SCEP_CONFIGURATION_PARAM_VERBOSE				"Verbose"
#define SCEP_CONFIGURATION_PARAM_RESUME					"Resume"
#define SCEP_CONFIGURATION_PARAM_MONITORINFO            "MonitorInformation"

#ifdef WIN32
#define SCEP_CONFIGURATION_DEFAULT_DYNAMICPATH_WINDOWS	"%s\\System32\\%s.dll"
#endif

/*
 * Holds the configuration of all parts that are new,
 * e.g. mostly engine stuff. In the futurue possibly
 * new options are added here and maybe even move all
 * current sscep parameters here but right now it is here
 * so new parameters can be defined more easily.
 */
typedef struct {
	struct scep_engine_conf_st *engine;
	char *engine_str;
} SCEP_CONF;

struct scep_engine_conf_st{
	char *engine_id; // ID of the engine according to OpenSSL (e.g. pkcs11, capi, chil, ...)
	char *new_key_location; // CryptoAPI only option: Which storename to set for the new key, default: REQUEST
	int storelocation; // CryptoAPI only option: Which storelocation to use, default: OpenSSL engine default
	char *dynamic_path; // where the shared object (.so, .dll) can be found
	char *jconnpath; //the JavaConnectorPath variable which needs to be set to use the Java part of JKSEngine
	char *storepass; // Passphrase for the JKS keystore (JKSEngine)
	char *provider; // Provider of the keystore (JKSEngine)
	char *javapath; // Path to Java (JKSEngine)
	char *pin; //the PIN used for the PKCS11 token, default: will be prompted (pkcs11)
	char *module_path; // see OpenSSL ctrl MODULE_PATH for engines (example: PKCS#11)
};

SCEP_CONF *scep_conf;

int scep_conf_init(char *filename);
int scep_conf_load(CONF *conf);
int scep_conf_load_operation_getca(CONF *conf);
int scep_conf_load_operation_enroll(CONF *conf);
int scep_conf_load_operation_getcert(CONF *conf);
int scep_conf_load_operation_getcrl(CONF *conf);
int scep_conf_load_operation_getnextca(CONF *conf);
void scep_dump_conf(void);
void error_memory(void);

#endif /* ifndef CONFIGURATION_H */
