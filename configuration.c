#include "configuration.h"

#ifdef WIN32
#define strdup(str) _strdup(str)
#define itoa _itoa
#endif

int scep_conf_init(char *filename) {
	long err;
	CONF *conf;

	if(filename == NULL) {
		return 0;
	}
	conf = NCONF_new(NCONF_default());
	if(!NCONF_load(conf, filename, &err)) {
		if(err == 0)
			fprintf(stderr, "%s: Error opening configuration file\n", pname);
		else {
			fprintf(stderr, "%s: Error in %s on line %li\n", pname, filename, err);
			ERR_print_errors_fp(stderr);
		}
		exit(SCEP_PKISTATUS_FILE);
	}
		
	scep_conf = malloc(sizeof(*scep_conf));
	scep_conf->engine = malloc(sizeof(struct scep_engine_conf_st));
	scep_conf->engine_str = NULL;
	if(scep_conf_load(conf) == 0 && v_flag) {
		//report something here?
	}
	return 0;
}


int scep_conf_load(CONF *conf) {

	char *engine_section, *var, *engine_special_section;

#ifdef WIN32
	char *windir;
#endif

	int ret;

	//load global scep vars
	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION, SCEP_CONFIGURATION_PARAM_CACERTFILE)) && !c_flag) {
		c_flag = 1;
		if(!(c_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION, SCEP_CONFIGURATION_PARAM_CAIDENTIFIER)) && !i_flag) {
		i_flag = 1;
		if(!(i_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION, SCEP_CONFIGURATION_PARAM_DEBUG)) && !d_flag) {
		if(!strncmp(var, "true", 3) && !d_flag)	
			d_flag = 1;
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION, SCEP_CONFIGURATION_PARAM_ENCALGORITHM)) && !E_flag) {
		E_flag = 1;
		if(!(E_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION, SCEP_CONFIGURATION_PARAM_SIGALGORITHM)) && !S_flag) {
		S_flag = 1;
		if(!(S_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION, SCEP_CONFIGURATION_PARAM_PROXY)) && !p_flag) {
		p_flag = 1;
		if(!(p_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION, SCEP_CONFIGURATION_PARAM_URL)) && !u_flag) {
		u_flag = 1;
		if(!(url_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION, SCEP_CONFIGURATION_PARAM_MONITORINFO)) && !M_flag) {
		M_flag = 1;
		if(!(M_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION, SCEP_CONFIGURATION_PARAM_VERBOSE)) && !v_flag) {
		if(!strncmp(var, "true", 3) && !v_flag)
			v_flag = 1;
	}

	//loading options for specific operation
	switch(operation_flag) {
		case SCEP_OPERATION_ENROLL:
			ret = scep_conf_load_operation_enroll(conf);
			break;
		case SCEP_OPERATION_GETCA:
			ret = scep_conf_load_operation_getca(conf);
			break;
		case SCEP_OPERATION_GETCERT:
			ret = scep_conf_load_operation_getcert(conf);
			break;
		case SCEP_OPERATION_GETCRL:
			ret = scep_conf_load_operation_getcrl(conf);
			break;
		case SCEP_OPERATION_GETNEXTCA:
			ret = scep_conf_load_operation_getnextca(conf);
			break;
		default:
			fprintf(stderr, "No operation specified, can't load specific settings!\n");
			ret = -1;
			break;
	}




	//load engine vars
	if(!(engine_section = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION, SCEP_CONFIGURATION_PARAM_ENGINE))) {
		if(d_flag) {
			printf("%s: No engine section specified, not loading an engine\n", pname);
		}
		scep_conf->engine_str = NULL;
		free(scep_conf->engine);
		scep_conf->engine = NULL;
	} else {
		//set the engine_str variable to save the section name
		scep_conf->engine_str = engine_section;
		if(!NCONF_get_section(conf, engine_section)) {
			fprintf(stderr, "%s: Section %s defined but not found!\n", pname, engine_section);
			exit(SCEP_PKISTATUS_FILE);
		}

		//engine is specified, lets load parameters
		if(d_flag) 
			printf("%s: Engine Section %s found and processing it\n", pname, SCEP_CONFIGURATION_PARAM_ENGINE);

		//getting engine ID
		if(var = NCONF_get_string(conf, engine_section, SCEP_CONFIGURATION_ENGINE_ID)) {
			if(v_flag)
				printf("%s: Configuration: Engine ID set to %s\n", pname, var);
			scep_conf->engine->engine_id = var;
		} else {
			fprintf(stderr, "%s: Engine ID not specified, cannot continue. Please provide an eninge ID\n", pname);
			exit(SCEP_PKISTATUS_FILE);
		}

		
        //write g_char, but ONLY if not defined already (command line overwrites config file)
		if(!g_flag) {
			g_flag = 1;
			g_char = strdup(scep_conf->engine->engine_id);
		}

		//load the special section string
		engine_special_section = (char *) malloc(sizeof(SCEP_CONFIGURATION_SECTION_ENGINE_TEMPLATE) + sizeof(scep_conf->engine->engine_id));
		sprintf(engine_special_section, SCEP_CONFIGURATION_SECTION_ENGINE_TEMPLATE, scep_conf->engine->engine_id);

		//load capi only option
		//TODO move
		if(strncmp(scep_conf->engine->engine_id, "capi", 4) == 0) {
			if(var = NCONF_get_string(conf, engine_special_section, SCEP_CONFIGURATION_ENGINE_CAPI_NEWKEYLOCATION)) {
				if(v_flag)
					printf("%s: Location of the new key will be in %s\n", pname, var);
				scep_conf->engine->new_key_location = var;
			} else {
				if(v_flag)
					printf("%s: No new key location was provided, using default \"REQUEST\"\n", pname);
				scep_conf->engine->new_key_location = "REQUEST";
			}

			if(var = NCONF_get_string(conf, engine_special_section, SCEP_CONFIGURATION_ENGINE_CAPI_STORELOCATION)) {
				if(v_flag)
					printf("%s: The store used will be %s\n", pname, var);
				if(!strncmp(var, "LOCAL_MACHINE", 13)) {
					scep_conf->engine->storelocation = 1;
				} else if(!strncmp(var, "CURRENT_USER", 12)) {
					scep_conf->engine->storelocation = 0;
				} else {
					printf("%s: Provided storename unknown (%s). Will use the engines default.\n", pname, var);
					scep_conf->engine->storelocation = 0;
				}
			} else {
				if(v_flag)
					printf("%s: No storename was provided. Will use the engines default.\n", pname);
				scep_conf->engine->storelocation = 0;
			}

			
		}

		//load JKSEngine only option
		//TODO move
		if(strncmp(scep_conf->engine->engine_id, "jksengine", 9) == 0) {
			if(var = NCONF_get_string(conf, engine_special_section, SCEP_CONFIGURATION_ENGINE_JKSENGINE_KEYSTOREPASS)) {
				if(v_flag)
					printf("%s: KeyStorePass will be set to %s\n", pname, var);
				scep_conf->engine->storepass = var;
			}

			if(var = NCONF_get_string(conf, engine_special_section, SCEP_CONFIGURATION_ENGINE_JKSENGINE_JCONNPATH)) {
				if(v_flag)
					printf("%s: JavaConnectorPath will be set to %s\n", pname, var);
				scep_conf->engine->jconnpath = var;
			}

			if(var = NCONF_get_string(conf, engine_special_section, SCEP_CONFIGURATION_ENGINE_JKSENGINE_PROVIDER)) {
				if(v_flag)
					printf("%s: KeyStoreProvider will be set to %s\n", pname, var);
				scep_conf->engine->provider = var;
			}

			if(var = NCONF_get_string(conf, engine_special_section, SCEP_CONFIGURATION_ENGINE_JKSENGINE_JAVAPATH)) {
				if(v_flag)
					printf("%s: JavaPath will be set to %s\n", pname, var);
				scep_conf->engine->javapath = var;
			}
		}

		//load PKCS11 only options
		//TODO move
		if(strncmp(scep_conf->engine->engine_id, "pkcs11", 6) == 0) {
			scep_conf->engine->pin = NULL;
			if(var = NCONF_get_string(conf, engine_special_section, SCEP_CONFIGURATION_ENGINE_PKCS11_PIN)) {
				if(v_flag)
					printf("%s: Setting PIN to configuration value\n", pname);
				scep_conf->engine->pin = var;
			}
		}

		//loading dynamic path variable
		if(var = NCONF_get_string(conf, engine_section, SCEP_CONFIGURATION_ENGINE_DYNPATH)) {
			if(v_flag)
				printf("%s: Setting dynamic dll path to %s\n", pname, var);
			scep_conf->engine->dynamic_path = var;
		} else {
			if(v_flag)
				printf("%s: Not setting a dynamic path. Not dynamic loading supported for engine %s\n", pname, scep_conf->engine->engine_id);
#ifdef WIN32
			//fallback does not work yet!
			//TODO: find out why it did not find the C:\Windows\System32\capi.dll
			windir = getenv("WINDIR");
			scep_conf->engine->dynamic_path = (char *) malloc(sizeof(SCEP_CONFIGURATION_DEFAULT_DYNAMICPATH_WINDOWS) + sizeof(scep_conf->engine->engine_id) + sizeof(windir));
			sprintf(scep_conf->engine->dynamic_path, SCEP_CONFIGURATION_DEFAULT_DYNAMICPATH_WINDOWS, getenv("WINDIR"), scep_conf->engine->engine_id);
#else
			scep_conf->engine->dynamic_path = NULL;
#endif
		}

		//loading module path variable
		if(var = NCONF_get_string(conf, engine_section, SCEP_CONFIGURATION_ENGINE_MODULEPATH)) {
			if(v_flag)
				printf("%s: Setting module path to %s\n", pname, var);
			scep_conf->engine->module_path = var;
		} else {
			scep_conf->engine->module_path = NULL;
			if(v_flag)
				printf("%s: No module path defined, not using/loading any module\n", pname);
		}

	}


	return 0;
}

int scep_conf_load_operation_getca(CONF *conf) {
	char *var;

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETCA, SCEP_CONFIGURATION_PARAM_CAIDENTIFIER)) && !i_flag) {
		i_flag = 1;
		if(!(i_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETCA, SCEP_CONFIGURATION_PARAM_FINGERPRINT)) && !F_flag) {
		F_flag = 1;
		if(!(F_char = strdup(var)))
			error_memory();
	}
	
	return 0;
}



int scep_conf_load_operation_getnextca(CONF *conf) {
	char *var;

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETNEXTCA, SCEP_CONFIGURATION_PARAM_CAIDENTIFIER)) && !i_flag) {
		i_flag = 1;
		if(!(i_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETNEXTCA, SCEP_CONFIGURATION_PARAM_CERTROOTCHAINFILE)) && !C_flag) {
		C_flag = 1;
		if(!(C_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETNEXTCA, SCEP_CONFIGURATION_PARAM_FINGERPRINT)) && !F_flag) {
		F_flag = 1;
		if(!(F_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETNEXTCA, SCEP_CONFIGURATION_PARAM_SIGNERCERTIFICATE)) && !w_flag) {
		w_flag = 1;
		if(!(w_char = strdup(var)))
			error_memory();
	}

	return 0;
}

int scep_conf_load_operation_enroll(CONF *conf) {
	char *var;

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_ENROLL, SCEP_CONFIGURATION_PARAM_PRIVATEKEYFILE)) && !k_flag) {
		k_flag = 1;
		if(!(k_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_ENROLL, SCEP_CONFIGURATION_PARAM_CERTREQFILE)) && !r_flag) {
		r_flag = 1;
		if(!(r_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_ENROLL, SCEP_CONFIGURATION_PARAM_SIGNKEYFILE)) && !K_flag) {
		K_flag = 1;
		if(!(K_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_ENROLL, SCEP_CONFIGURATION_PARAM_SIGNCERTFILE)) && !O_flag) {
		O_flag = 1;
		if(!(O_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_ENROLL, SCEP_CONFIGURATION_PARAM_LOCALCERTFILE)) && !l_flag) {
		l_flag = 1;
		if(!(l_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_ENROLL, SCEP_CONFIGURATION_PARAM_ENCCERTFILE)) && !e_flag) {
		e_flag = 1;
		if(!(e_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_ENROLL, SCEP_CONFIGURATION_PARAM_SELFSIGNEDFILE)) && !L_flag) {
		L_flag = 1;
		if(!(L_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_ENROLL, SCEP_CONFIGURATION_PARAM_POLLINTERVAL)) && !t_flag) {
		t_flag = 1;
		t_num = atoi(var);
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_ENROLL, SCEP_CONFIGURATION_PARAM_MAXPOLLTIME)) && !T_flag) {
		T_flag = 1;
		T_num = atoi(var);
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_ENROLL, SCEP_CONFIGURATION_PARAM_MAXPOLLCOUNT)) && !n_flag) {
		n_flag = 1;
		n_num = atoi(var);
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_ENROLL, SCEP_CONFIGURATION_PARAM_RESUME)) && !R_flag) {
		if(!strncmp(var, "true", 3) && !R_flag)
			R_flag = 1;
	}
	return 0;
}

int scep_conf_load_operation_getcert(CONF *conf) {
	char *var;
	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETCERT, SCEP_CONFIGURATION_PARAM_PRIVATEKEYFILE)) && !k_flag) {
		k_flag = 1;
		if(!(k_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETCERT, SCEP_CONFIGURATION_PARAM_LOCALCERTFILE)) && !l_flag) {
		l_flag = 1;
		if(!(l_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETCERT, SCEP_CONFIGURATION_PARAM_GETCERTSERIAL)) && !s_flag) {
		s_flag = 1;
		if(!(s_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETCERT, SCEP_CONFIGURATION_PARAM_GETCERTFILE)) && !w_flag) {
		w_flag = 1;
		if(!(w_char = strdup(var)))
			error_memory();
	}
	
	return 0;
}

int scep_conf_load_operation_getcrl(CONF *conf) {
	char *var;
	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETCRL, SCEP_CONFIGURATION_PARAM_PRIVATEKEYFILE)) && !k_flag) {
		k_flag = 1;
		if(!(k_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETCRL, SCEP_CONFIGURATION_PARAM_LOCALCERTFILE)) && !l_flag) {
		l_flag = 1;
		if(!(l_char = strdup(var)))
			error_memory();
	}

	if((var = NCONF_get_string(conf, SCEP_CONFIGURATION_SECTION_GETCRL, SCEP_CONFIGURATION_PARAM_GETCRLFILE)) && !w_flag) {
		w_flag = 1;
		if(!(w_char = strdup(var)))
			error_memory();
	}

	return 0;
}

void error_memory() {
	fprintf(stderr, "%s: memory allocation failure, errno: %d\n",
		pname, errno);
	exit(1);
}

void scep_dump_conf() {

	char *T_char , *n_char, *t_char;
	int flags[] = {
		c_flag, i_flag, r_flag, d_flag, e_flag, E_flag, F_flag, w_flag, s_flag, l_flag, O_flag, n_flag, T_flag,
		k_flag, K_flag, L_flag, S_flag, p_flag, t_flag, u_flag, v_flag, R_flag
	};
	char *chars[] = {
		c_char, i_char, r_char, "true", e_char, E_char, F_char, w_char, s_char, l_char, O_char, "", "",
		k_char, K_char, L_char, S_char, p_char, "", url_char, "true", "true"
	};
	char *names[] = {
		"-c / CACertFile",
		"-i / CAIdentifier",
		"-r / CertReqFile",
		"-d / Debug", 
		"-e / EncCertFile",
		"-E / EncAlgorithm", 
		"-F / FingerPrint",
		"-w / GetCertFile od. GetCrlFile",
		"-s / GetCertSerial",
		"-l / LocalCertFile",
		"-O / SignCertFile",
		"-n / MaxPollCount",
		"-T / MaxPollTime",
		"-k / PrivateKeyFile",
		"-K / SignKeyFile",
		"-L / SelfSignedFile",
		"-S / SigAlgorithm",
		"-p / Proxy",
		"-t / PollInterval",
		"-u / URL",
		"-v / Verbose",
		"-R / Resume"
	};
	
	T_char = (char *) malloc(sizeof(char) * 20);
	n_char = (char *) malloc(sizeof(char) * 20);
	t_char = (char *) malloc(sizeof(char) * 20);
	sprintf(T_char, "%d", T_num);
	chars[12] = T_char;
	sprintf(n_char, "%d", n_num);
	chars[11] = n_char;
	sprintf(t_char, "%d", t_num);
	chars[18] = t_char;

	printf("Dumping Configuration\n");

	if(sizeof(chars)/sizeof(char *) == sizeof(names)/sizeof(char *)) {
		int i;
		for(i = 0; i<sizeof(flags)/sizeof(int); i++) {
			if(flags[i])
				printf("Option: %s, Flag: %i, Value: %s\n", names[i], flags[i], chars[i]);
		}
	} else {
		fprintf(stderr, "Length of Arrays does not match! Flags: %i, Chars: %i, Names: %i\n",
			sizeof(flags)/sizeof(int),
			sizeof(chars)/sizeof(char *),
			sizeof(names)/sizeof(char *)
		);
	}
	exit(0);
}
