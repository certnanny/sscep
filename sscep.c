
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */


/* Main routine */


#include "sscep.h"

static char *
handle_serial (char * serial)
{
	int hex = NULL != strchr (serial, ':');

	/* Convert serial to a decimal serial when input is
	   a hexidecimal representation of the serial */
	if (hex)
	{
		unsigned int i,ii;
		char *tmp_serial = (char*) calloc (strlen (serial) + 1,1);

		for (i=0,ii=0; '\0'!=serial[i];i++)
		{
			if (':'!=serial[i])
				tmp_serial[ii++]=serial[i];
		}
		serial=tmp_serial;
	}
	else
	{
		unsigned int i;
		for (i=0; ! hex && '\0' != serial[i]; i++)
			hex = 'a'==serial[i]||'b'==serial[i]||'c'==serial[i]||'d'==serial[i]||'e'==serial[i]||'f'==serial[i];
	}

	if (hex)
	{
		ASN1_INTEGER* ai;
 		BIGNUM *ret;
 		BIO* in = BIO_new_mem_buf(serial, -1);
  		char buf[1025];
  		ai=ASN1_INTEGER_new();
  		if (ai == NULL) return NULL;
   		if (!a2i_ASN1_INTEGER(in,ai,buf,1024))
   		{
			return NULL;
   		}
   		ret=ASN1_INTEGER_to_BN(ai,NULL);
   		if (ret == NULL)
   		{
			return NULL;
   		}
   		else
   		{
    		 serial = BN_bn2dec(ret);
   		}
  	}

	return serial;
} /* handle_serial */

int
main(int argc, char **argv) {
	//ENGINE *e = NULL;
	int			c, host_port = 80, count = 1;
	char			*host_name, *p, *dir_name = NULL;
	char			http_string[16384];
	struct http_reply	reply;
	unsigned int		n;
	unsigned char		md[EVP_MAX_MD_SIZE];
	struct scep		scep_t;
	FILE			*fp = NULL;
	BIO			*bp;
	STACK_OF(X509)		*nextcara = NULL;
	X509 				*cert=NULL;
	PKCS7 p7;
	int i;
	int required_option_space;
	


#ifdef WIN32
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;
	//printf("Starting sscep\n");
	//fprintf(stdout, "%s: starting sscep on WIN32, sscep version %s\n",	pname, VERSION);
       
	wVersionRequested = MAKEWORD( 2, 2 );
 
	err = WSAStartup( wVersionRequested, &wsaData );
	if ( err != 0 )
	{
	  /* Tell the user that we could not find a usable */
	  /* WinSock DLL.                                  */
	  return;
	}
 
	/* Confirm that the WinSock DLL supports 2.2.*/
	/* Note that if the DLL supports versions greater    */
	/* than 2.2 in addition to 2.2, it will still return */
	/* 2.2 in wVersion since that is the version we      */
	/* requested.                                        */
 
	if ( LOBYTE( wsaData.wVersion ) != 2 ||
	        HIBYTE( wsaData.wVersion ) != 2 )
	{
	    /* Tell the user that we could not find a usable */
	    /* WinSock DLL.                                  */
	    WSACleanup( );
	    return; 
	}

#endif
	/* Initialize scep layer */
	init_scep();

	/* Set program name */
	pname = argv[0];

	/* Set timeout */
	timeout = TIMEOUT;


	/* Check operation parameter */
	if (!argv[1]) {
		usage();
	} else if (!strncmp(argv[1], "getca", 5)) {
		operation_flag = SCEP_OPERATION_GETCA;
	} else if (!strncmp(argv[1], "enroll", 6)) {
		operation_flag = SCEP_OPERATION_ENROLL;
	} else if (!strncmp(argv[1], "getcert", 7)) {
		operation_flag = SCEP_OPERATION_GETCERT;
	} else if (!strncmp(argv[1], "getcrl", 6)) {
		operation_flag = SCEP_OPERATION_GETCRL;
	} else if (!strncmp(argv[1], "getnextca", 9)) {
		operation_flag = SCEP_OPERATION_GETNEXTCA;
	} else {
		fprintf(stderr, "%s: missing or illegal operation parameter\n",
				argv[0]);
		usage();
	}
	/* Skip first parameter and parse the rest of the command */
	optind++;
	while ((c = getopt(argc, argv, "c:C:de:E:f:g:hF:i:k:K:l:L:n:O:p:r:Rs:S:t:T:u:vw:m:HM:")) != -1)
                switch(c) {
			case 'c':
				c_flag = 1;
				c_char = optarg;
				break;
			case 'C':
				C_flag = 1;
				C_char = optarg;
				break;
			case 'd':
				d_flag = 1;
				break;
			case 'e':
				e_flag = 1;
				e_char = optarg;
				break;
			case 'E':
				E_flag = 1;
				E_char = optarg;
				break;
			case 'F':
				F_flag = 1;
				F_char = optarg;
				break;
			case 'f':
				f_flag = 1;
				f_char = optarg;
				break;
			case 'g':
				g_flag = 1;
				g_char = optarg;
				break;
			case 'h'://TODO change to eg. ID --inform=ID
				h_flag = 1;
				break;
			case 'H':
				H_flag = 1;
				break;
			case 'i':
				i_flag = 1;
				i_char = optarg;
				break;
			case 'k':
				k_flag = 1;
				k_char = optarg;
				break;
			case 'K':
				K_flag = 1;
				K_char = optarg;
				break;
			case 'l':
				l_flag = 1;
				l_char = optarg;
				break;
			case 'L':
				L_flag = 1;
				L_char = optarg;
				break;
			case 'm':
				m_flag = 1;
				m_char = optarg;
				break;
			case 'M':
				if(!M_flag) {
					/* if this is the first time the option appears, create a
					 * new string.
					 */
					required_option_space = strlen(optarg) + 1;
					M_char = malloc(required_option_space);
					if(!M_char)
						error_memory();
					strncpy(M_char, optarg, required_option_space);
					// set the flag, so we already have a string
					M_flag = 1;
				} else {
					/* we already have a string, just extend it. */
					// old part + new part + &-sign + null byte
					required_option_space = strlen(M_char) + strlen(optarg) + 2;
					M_char = realloc(M_char, required_option_space);
					if(!M_char)
						error_memory();
					strncat(M_char, "&", 1);
					strncat(M_char, optarg, strlen(optarg));
				}
				break;
			case 'n':
				n_flag = 1;
				n_num = atoi(optarg);
				break;
			case 'O':
				O_flag = 1;
				O_char = optarg;
				break;
			case 'p':
				p_flag = 1;
				p_char = optarg;
				break;
			case 'r':
				r_flag = 1;
				r_char = optarg;
				break;
			case 'R':
				R_flag = 1;
				break;
			case 's':
				s_flag = 1;
				/*s_char = optarg;*/
				s_char = handle_serial(optarg);
				break;
			case 'S':
				S_flag = 1;
				S_char = optarg;
				break;
			case 't':
				t_flag = 1;
				t_num = atoi(optarg);
				break;
			case 'T':
				T_flag = 1;
				T_num = atoi(optarg);
				break;
			case 'u':
				u_flag = 1;
				url_char = optarg;
				break;
			case 'v':
				v_flag = 1;
				break;
			case 'w':
				w_flag = 1;
				w_char = optarg;
				break;
			default:
			  printf("argv: %s\n", argv[optind]);
				usage();
                }
	argc -= optind;
	argv += optind;

	/* If we debug, include verbose messages also */
	if (d_flag)
		v_flag = 1;
	
	if(f_char){
		scep_conf_init(f_char);
	}else{
		scep_conf = NULL;    //moved init to here otherwise compile error on windows
	}
	/* Read in the configuration file: */
	/*if (f_char) {
	#ifdef WIN32
		if ((fopen_s(&fp, f_char, "r")))
	#else
		if (!(fp = fopen(f_char, "r")))
	#endif
			fprintf(stderr, "%s: cannot open %s\n", pname, f_char);
		else {
			init_config(fp);
			(void)fclose(fp);
		}
	}*/
	if (v_flag)
		fprintf(stdout, "%s: starting sscep, version %s\n",
			pname, VERSION);

	/*
	* Create a new SCEP transaction and self-signed
	* certificate based on cert request
	*/
	if (v_flag)
		fprintf(stdout, "%s: new transaction\n", pname);
	new_transaction(&scep_t);

	/*enable Engine Support */
	if (g_flag) {
		scep_t.e = scep_engine_init(scep_t.e);
	}
	
	/*
	 * Check argument logic.
	 */
	if (!c_flag) {
		if (operation_flag == SCEP_OPERATION_GETCA) {
			fprintf(stderr,
			  "%s: missing CA certificate filename (-c)\n", pname);
			exit (SCEP_PKISTATUS_ERROR);
		} else {
			fprintf(stderr,
				"%s: missing CA certificate (-c)\n", pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
		if (operation_flag == SCEP_OPERATION_GETNEXTCA) {
			fprintf(stderr,
			  "%s: missing nextCA certificate target filename (-c)\n", pname);
			exit (SCEP_PKISTATUS_ERROR);
		} else {
			fprintf(stderr,
				"%s: missing nextCA certificate target filename(-c)\n", pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
	}
	if (!C_flag) {
		if (operation_flag == SCEP_OPERATION_GETNEXTCA) {
			fprintf(stderr,
			  "%s: missing nextCA certificate chain filename (-C)\n", pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
	}
	if (operation_flag == SCEP_OPERATION_ENROLL) {
		if (!k_flag) {
			fprintf(stderr, "%s: missing private key (-k)\n",pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
		if (!r_flag) {
			fprintf(stderr, "%s: missing request (-r)\n",pname);
			exit (SCEP_PKISTATUS_ERROR);

		}
		if (!l_flag) {
			fprintf(stderr, "%s: missing local cert (-l)\n",pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
		/* Set polling limits */
		if (!n_flag)
			n_num = MAX_POLL_COUNT;
		if (!t_flag)
			t_num = POLL_TIME;
		if (!T_flag)
			T_num = MAX_POLL_TIME;
	}
	if (operation_flag == SCEP_OPERATION_GETCERT) {
		if (!l_flag) {
			fprintf(stderr, "%s: missing local cert (-l)\n",pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
		if (!s_flag) {
			fprintf(stderr, "%s: missing serial no (-s)\n", pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
		if (!w_flag) {
			fprintf(stderr, "%s: missing cert file (-w)\n",pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
		if (!k_flag) {
			fprintf(stderr, "%s: missing private key (-k)\n",pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
	}
	if (operation_flag == SCEP_OPERATION_GETCRL) {
		if (!l_flag) {
			fprintf(stderr, "%s: missing local cert (-l)\n",pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
		if (!w_flag) {
			fprintf(stderr, "%s: missing crl file (-w)\n",pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
		if (!k_flag) {
			fprintf(stderr, "%s: missing private key (-k)\n",pname);
			exit (SCEP_PKISTATUS_ERROR);
		}
	}

	/* Break down the URL */
	if (!u_flag) {
		fprintf(stderr, "%s: missing URL (-u)\n", pname);
		exit (SCEP_PKISTATUS_ERROR);
	}
	if (strncmp(url_char, "http://", 7) && !p_flag) {
		fprintf(stderr, "%s: illegal URL %s\n", pname, url_char);
		exit (SCEP_PKISTATUS_ERROR);
	}
	if (p_flag) {
		#ifdef WIN32
		host_name = _strdup(p_char);
		#else
		host_name = strdup(p_char);
		#endif
		dir_name = url_char;
	}

	/* Break down the URL */
	if (!u_flag) {
		fprintf(stderr, "%s: missing URL (-u)\n", pname);
		exit (SCEP_PKISTATUS_ERROR);
	}
	if (strncmp(url_char, "http://", 7) && !p_flag) {
		fprintf(stderr, "%s: illegal URL %s\n", pname, url_char);
		exit (SCEP_PKISTATUS_ERROR);
	}
	if (p_flag) {
		#ifdef WIN32
		host_name = _strdup(p_char);
		#else
		host_name = strdup(p_char);
		#endif
		dir_name = url_char;
	}
	#ifdef WIN32
	else if (!(host_name = _strdup(url_char + 7)))
	#else
	else if (!(host_name = strdup(url_char + 7)))
	#endif
		error_memory();
	p = host_name;
	c = 0;
	while (*p != '\0') {
		if (*p == '/' && !p_flag && !c) {
			*p = '\0';
			if (*(p+1)) dir_name = p + 1;
			c = 1;
		}
		if (*p == ':') {
			*p = '\0';
			if (*(p+1)) host_port = atoi(p+1);
		}
		p++;
	}
	if (!dir_name) {
		fprintf(stderr, "%s: illegal URL %s\n", pname, url_char);
		exit (SCEP_PKISTATUS_ERROR);
	}
	if (host_port < 1 || host_port > 65550) {
		fprintf(stderr, "%s: illegal port number %d\n", pname,
				host_port);
		exit (SCEP_PKISTATUS_ERROR);
	}
	if (v_flag) {
		fprintf(stdout, "%s: hostname: %s\n", pname, host_name);
		fprintf(stdout, "%s: directory: %s\n", pname, dir_name);
		fprintf(stdout, "%s: port: %d\n", pname, host_port);
	}

	/* Check algorithms */
	if (!E_flag) {
		enc_alg = (EVP_CIPHER *)EVP_des_cbc();
	} else if (!strncmp(E_char, "blowfish", 8)) {
		enc_alg = (EVP_CIPHER *)EVP_bf_cbc();
	} else if (!strncmp(E_char, "des", 3)) {
		enc_alg = (EVP_CIPHER *)EVP_des_cbc();
	} else if (!strncmp(E_char, "3des", 4)) {
		enc_alg = (EVP_CIPHER *)EVP_des_ede3_cbc();
	} else {
		fprintf(stderr, "%s: unsupported algorithm: %s\n",
			pname, E_char);
		exit (SCEP_PKISTATUS_ERROR);
	}
	if (!S_flag) {
		sig_alg = (EVP_MD *)EVP_md5();
	} else if (!strncmp(S_char, "md5", 3)) {
		sig_alg = (EVP_MD *)EVP_md5();
	} else if (!strncmp(S_char, "sha1", 4)) {
		sig_alg = (EVP_MD *)EVP_sha1();
	} else {
		fprintf(stderr, "%s: unsupported algorithm: %s\n",
			pname, S_char);
		exit (SCEP_PKISTATUS_ERROR);
	}
	/* Fingerprint algorithm */
	if (!F_flag) {
		fp_alg = (EVP_MD *)EVP_md5();
	} else if (!strncmp(F_char, "md5", 3)) {
		fp_alg = (EVP_MD *)EVP_md5();
	} else if (!strncmp(F_char, "sha1", 4)) {
		fp_alg = (EVP_MD *)EVP_sha1();
	} else {
		fprintf(stderr, "%s: unsupported algorithm: %s\n",
			pname, F_char);
		exit (SCEP_PKISTATUS_ERROR);
	}

	/*
	 * Switch to operation specific code
	 */
	switch(operation_flag) {
		case SCEP_OPERATION_GETCA:
			if (v_flag)
				fprintf(stdout, "%s: SCEP_OPERATION_GETCA\n",
					pname);

			/* Set CA identifier */
			if (!i_flag)
				i_char = CA_IDENTIFIER;

			/* Forge the HTTP message */

			if(!M_flag){
				snprintf(http_string, sizeof(http_string),
				 "GET %s%s?operation=GetCACert&message=%s "
				 "HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name,
						i_char);

			}else{
				snprintf(http_string, sizeof(http_string),
					"GET %s%s?operation=GetCACert&message=%s&%s "
					"HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name,
						i_char, M_char);

			}



			if (d_flag){
				printf("%s: requesting CA certificate\n", pname);
				fprintf(stdout, "%s: scep msg: %s", pname,
									http_string);
			}

			/*
			 * Send http message.
			 * Response is written to http_response struct "reply".
			 */
			reply.payload = NULL;
			if ((c = send_msg (&reply, http_string, host_name,
					host_port, operation_flag)) == 1) {
				fprintf(stderr, "%s: error while sending "
					"message\n", pname);
				exit (SCEP_PKISTATUS_NET);
			}
			if (reply.payload == NULL) {
				fprintf(stderr, "%s: no data, perhaps you "
				   "should define CA identifier (-i)\n", pname);
				exit (SCEP_PKISTATUS_SUCCESS);
			}
			if (v_flag){
				printf("%s: valid response from server\n", pname);
			}
			if (reply.type == SCEP_MIME_GETCA_RA) {
				/* XXXXXXXXXXXXXXXXXXXXX chain not verified */
				write_ca_ra(&reply);
			}
			/* Read payload as DER X.509 object: */
			bp = BIO_new_mem_buf(reply.payload, reply.bytes);
			cacert = d2i_X509_bio(bp, NULL);

			/* Read and print certificate information */
			if (!X509_digest(cacert, fp_alg, md, &n)) {
				ERR_print_errors_fp(stderr);
				exit (SCEP_PKISTATUS_ERROR);
			}
			if (v_flag){
				printf("%s: %s fingerprint: ", pname,
					OBJ_nid2sn(EVP_MD_type(fp_alg)));
				for (c = 0; c < (int)n; c++) {
					printf("%02X%c",md[c],
						(c + 1 == (int)n) ?'\n':':');
				}

			}

			/* Write PEM-formatted file: */
			#ifdef WIN32
			if ((fopen_s(&fp,c_char , "w")))
			#else
			if (!(fp = fopen(c_char, "w")))
			#endif
			{
				fprintf(stderr, "%s: cannot open CA file for "
					"writing\n", pname);
				exit (SCEP_PKISTATUS_ERROR);
			}
			if (PEM_write_X509(fp, c_char) != 1) {
				fprintf(stderr, "%s: error while writing CA "
					"file\n", pname);
				ERR_print_errors_fp(stderr);
				exit (SCEP_PKISTATUS_ERROR);
			}
			if (v_flag)
			printf("%s: CA certificate written as %s\n",
				pname, c_char);
			(void)fclose(fp);
			pkistatus = SCEP_PKISTATUS_SUCCESS;
			break;

		case SCEP_OPERATION_GETNEXTCA:
				if (v_flag)
					fprintf(stdout, "%s: SCEP_OPERATION_GETNEXTCA\n",
						pname);

				/* Set CA identifier */
				if (!i_flag)
					i_char = CA_IDENTIFIER;

				/* Forge the HTTP message */
				if(!M_flag){
					snprintf(http_string, sizeof(http_string),
					 "GET %s%s?operation=GetNextCACert&message=%s "
					 "HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name,
							i_char);

				}else{
					snprintf(http_string, sizeof(http_string),
						"GET %s%s?operation=GetNextCACert&message=%s&%s "
						"HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name,
							i_char, M_char);

				}


				if (d_flag){
					printf("%s: requesting nextCA certificate\n", pname);
					fprintf(stdout, "%s: scep msg: %s", pname,
						http_string);
				}

				/*
				 * Send http message.
				 * Response is written to http_response struct "reply".
				 */
				reply.payload = NULL;
				if ((c = send_msg (&reply, http_string, host_name,
						host_port, operation_flag)) == 1) {
					if(v_flag){
					fprintf(stderr, "%s: error while sending "
						"message\n", pname);
					fprintf(stderr, "%s: getnextCA might be not available"
											"\n", pname);
					}
					exit (SCEP_PKISTATUS_NET);
				}
				if (reply.payload == NULL) {
					fprintf(stderr, "%s: no data, perhaps you "
					   "there is no nextCA available\n", pname);
					exit (SCEP_PKISTATUS_SUCCESS);
				}

				if(d_flag)
				printf("%s: valid response from server\n", pname);

				if (reply.type == SCEP_MIME_GETNEXTCA) {
					/* XXXXXXXXXXXXXXXXXXXXX chain not verified */

					//write_ca_ra(&reply);

					/* Set the whole struct as 0 */
					memset(&scep_t, 0, sizeof(scep_t));

					scep_t.reply_payload = reply.payload;
					scep_t.reply_len = reply.bytes;
					scep_t.request_type = SCEP_MIME_GETNEXTCA;

					pkcs7_verify_unwrap(&scep_t , C_char);

					//pkcs7_unwrap(&scep_t);
				}


				/* Get certs */
				p7 = *(scep_t.reply_p7);
				nextcara = scep_t.reply_p7->d.sign->cert;

			    if (v_flag) {
					printf ("verify and unwrap: found %d cert(s)\n", sk_X509_num(nextcara));
			        }

			    for (i = 0; i < sk_X509_num(nextcara); i++) {
			    		char buffer[1024];
			    		char name[1024];
			    		memset(buffer, 0, 1024);
			    		memset(name, 0, 1024);

			    		cert = sk_X509_value(nextcara, i);
			    		if (v_flag) {
			    			printf("%s: found certificate with\n"
			    				"  subject: '%s'\n", pname,
			    				X509_NAME_oneline(X509_get_subject_name(cert),
			    					buffer, sizeof(buffer)));
			    			printf("  issuer: %s\n",
			    				X509_NAME_oneline(X509_get_issuer_name(cert),
			    					buffer, sizeof(buffer)));
			    		}

			    		/* Create name */
			    		snprintf(name, 1024, "%s-%d", c_char, i);


			    		/* Write PEM-formatted file: */
			    		if (!(fp = fopen(name, "w"))) {
			    			fprintf(stderr, "%s: cannot open cert file for writing\n",
			    					pname);
			    			exit (SCEP_PKISTATUS_FILE);
			    		}
			    		if (v_flag)
			    			printf("%s: writing cert\n", pname);
			    		if (d_flag)
			    			PEM_write_X509(stdout, cert);
			    		if (PEM_write_X509(fp, cert) != 1) {
			    			fprintf(stderr, "%s: error while writing certificate "
			    				"file\n", pname);
			    			ERR_print_errors_fp(stderr);
			    			exit (SCEP_PKISTATUS_FILE);
			    		}
			    		if(v_flag)
			    		printf("%s: certificate written as %s\n", pname, name);
			    		(void)fclose(fp);
			    }



				pkistatus = SCEP_PKISTATUS_SUCCESS;
				break;

		case SCEP_OPERATION_GETCERT:
		case SCEP_OPERATION_GETCRL:
			/* Read local certificate */
			if (!l_flag) {
			  fprintf(stderr, "%s: missing local cert (-l)\n", pname);
			  exit (SCEP_PKISTATUS_FILE);
			}
			read_cert(&localcert, l_char);

		case SCEP_OPERATION_ENROLL:
			/*
			 * Read in CA cert, private key and certificate
			 * request in global variables.
			 */

		        read_ca_cert();

			if (!k_flag) {
			  fprintf(stderr, "%s: missing private key (-k)\n", pname);
			  exit (SCEP_PKISTATUS_FILE);
			}
			
			if(scep_conf != NULL) {
				sscep_engine_read_key_new(&rsa, k_char, scep_t.e);
			} else {
				read_key(&rsa, k_char);
			}


			if ((K_flag && !O_flag) || (!K_flag && O_flag)) {
			  fprintf(stderr, "%s: -O also requires -K (and vice-versa)\n", pname);
			  exit (SCEP_PKISTATUS_FILE);
			}

			if (K_flag) {
				//TODO auf hwcrhk prfen?
				if(scep_conf != NULL) {
					sscep_engine_read_key_old(&renewal_key, K_char, scep_t.e);
				} else {
					read_key(&renewal_key, K_char);
				}
			}

			if (O_flag) {
				read_cert(&renewal_cert, O_char);
			}

			if (operation_flag == SCEP_OPERATION_ENROLL) {
				read_request();
				scep_t.transaction_id = key_fingerprint(request);			
				if (v_flag) {
					printf("%s:  Read request with transaction id: %s\n", pname, scep_t.transaction_id);
				}
			}

			
			if (operation_flag != SCEP_OPERATION_ENROLL)
				goto not_enroll;
			
			if (! O_flag) {
				if (v_flag)
					fprintf(stdout, "%s: generating selfsigned "
					"certificate\n", pname);
			  new_selfsigned(&scep_t);
			}
			else {
			  /* Use existing certificate */
			  scep_t.signercert = renewal_cert;
			  scep_t.signerkey = renewal_key;
			}

			/* Write the selfsigned certificate if requested */
			if (L_flag) {
				/* Write PEM-formatted file: */
				#ifdef WIN32
				if ((fopen_s(&fp, L_char, "w"))) {
				#else
				if (!(fp = fopen(L_char, "w"))) {
				#endif
					fprintf(stderr, "%s: cannot open "
					  "file for writing\n", pname);
					exit (SCEP_PKISTATUS_ERROR);
				}
				if (PEM_write_X509(fp,scep_t.signercert) != 1) {
					fprintf(stderr, "%s: error while "
					  "writing certificate file\n", pname);
					ERR_print_errors_fp(stderr);
					exit (SCEP_PKISTATUS_ERROR);
				}
				printf("%s: selfsigned certificate written "
					"as %s\n", pname, L_char);
				(void)fclose(fp);
			}
			/* Write issuer name and subject (GetCertInitial): */
			if (!(scep_t.ias_getcertinit->subject =
					X509_REQ_get_subject_name(request))) {
				fprintf(stderr, "%s: error getting subject "
					"for GetCertInitial\n", pname);
				ERR_print_errors_fp(stderr);
				exit (SCEP_PKISTATUS_ERROR);
			}
not_enroll:
			if (!(scep_t.ias_getcertinit->issuer =
					 X509_get_issuer_name(cacert))) {
				fprintf(stderr, "%s: error getting issuer "
					"for GetCertInitial\n", pname);
				ERR_print_errors_fp(stderr);
				exit (SCEP_PKISTATUS_ERROR);
			}
			/* Write issuer name and serial (GETC{ert,rl}): */
			scep_t.ias_getcert->issuer =
				 scep_t.ias_getcertinit->issuer;
			scep_t.ias_getcrl->issuer =
				 scep_t.ias_getcertinit->issuer;
			if (!(scep_t.ias_getcrl->serial =
					X509_get_serialNumber(cacert))) {
				fprintf(stderr, "%s: error getting serial "
					"for GetCertInitial\n", pname);
				ERR_print_errors_fp(stderr);
				exit (SCEP_PKISTATUS_ERROR);
			}
			/* User supplied serial number */
			if (s_flag) {
				BIGNUM *bn;
				ASN1_INTEGER *ai;
				int len = BN_dec2bn(&bn , s_char);
				if (!len || !(ai = BN_to_ASN1_INTEGER(bn, NULL))) {
					fprintf(stderr, "%s: error converting serial\n", pname);
					ERR_print_errors_fp(stderr);
					exit (SCEP_PKISTATUS_SS);
				 }
				 scep_t.ias_getcert->serial = ai;
			}
		break;
	}

	switch(operation_flag) {
		case SCEP_OPERATION_ENROLL:
			if (v_flag)
				fprintf(stdout,
					"%s: SCEP_OPERATION_ENROLL\n", pname);
			/* Resum mode: set GetCertInitial */
			if (R_flag) {
				if (n_num == 0)
					exit (SCEP_PKISTATUS_SUCCESS);
				printf("%s: requesting certificate (#1)\n",
					pname);
				scep_t.request_type = SCEP_REQUEST_GETCERTINIT;
				count++;
			} else {
				printf("%s: sending certificate request\n",
					pname);
				scep_t.request_type = SCEP_REQUEST_PKCSREQ;
			}
			break;

		case SCEP_OPERATION_GETCERT:
			if (v_flag)
				fprintf(stdout,
					"%s: SCEP_OPERATION_GETCERT\n", pname);

			scep_t.request_type = SCEP_REQUEST_GETCERT;
			printf("%s: requesting certificate\n",pname);
			break;

		case SCEP_OPERATION_GETCRL:
			if (v_flag)
				fprintf(stdout,
					"%s: SCEP_OPERATION_GETCRL\n", pname);

			scep_t.request_type = SCEP_REQUEST_GETCRL;
			printf("%s: requesting crl\n",pname);
			break;
		}

		/* Enter polling loop */
		while (scep_t.pki_status != SCEP_PKISTATUS_SUCCESS) {
			/* create payload */
			pkcs7_wrap(&scep_t);

			/* URL-encode */
			p = url_encode((char *)scep_t.request_payload,
				scep_t.request_len);

			/*Test mode print SCEP request and don't send it*/
			if(m_flag){

				/* Write output file : */
#ifdef WIN32
				if ((fopen_s(&fp, m_char, "w")))
#else
				if (!(fp = fopen(m_char, "w")))
#endif
				{
					fprintf(stderr, "%s: cannot open output file for "
						"writing\n", m_char);
				}else
				{
					printf("%s: writing PEM fomatted PKCS#7\n", pname);
							PEM_write_PKCS7(fp, scep_t.request_p7);
				}

				//printf("Print SCEP Request:\n %s\n",scep_t.request_payload);
				return 0;
			}

			/* Forge the HTTP message */
		/*	snprintf(http_string, sizeof(http_string),
				"GET %s%s?operation="
				"PKIOperation&message="
				"%s HTTP/1.0\r\n\r\n",
				p_flag ? "" : "/", dir_name, p);*/

			if(!M_flag){
				snprintf(http_string, sizeof(http_string),
				 "GET %s%s?operation=PKIOperation&message=%s "
				 "HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name, p);

			}else{
				snprintf(http_string, sizeof(http_string),
					"GET %s%s?operation=PKIOperation&message=%s&%s "
					"HTTP/1.0\r\n\r\n", p_flag ? "" : "/", dir_name,p, M_char);

			}

			if (d_flag)
				fprintf(stdout, "%s: scep msg: %s",
					pname, http_string);

			/* send http */
			reply.payload = NULL;
			if ((c = send_msg (&reply, http_string, host_name,
					host_port, operation_flag)) == 1) {
				fprintf(stderr, "%s: error while sending "
					"message\n", pname);
				exit (SCEP_PKISTATUS_NET);
			}
			/* Verisign Onsite returns strange reply...
			 * XXXXXXXXXXXXXXXXXXX */
			if ((reply.status == 200) && (reply.payload == NULL)) {
				/*
				scep_t.pki_status = SCEP_PKISTATUS_PENDING;
				break;
				*/
				exit (SCEP_PKISTATUS_ERROR);
			}
			printf("%s: valid response from server\n", pname);

			/* Check payload */
			scep_t.reply_len = reply.bytes;
			scep_t.reply_payload = (unsigned char *)reply.payload;
			pkcs7_unwrap(&scep_t);
			pkistatus = scep_t.pki_status;

			switch(scep_t.pki_status) {
				case SCEP_PKISTATUS_SUCCESS:
					break;
				case SCEP_PKISTATUS_PENDING:
					/* Check time limits */
					if (((t_num * count) >= T_num) ||
					    (count > n_num)) {
						exit (pkistatus);
					}
					scep_t.request_type =
						SCEP_REQUEST_GETCERTINIT;

					/* Wait for poll interval */
					if (v_flag)
					  printf("%s: waiting for %d secs\n",
						pname, t_num);
					sleep(t_num);
					printf("%s: requesting certificate "
						"(#%d)\n", pname, count);

					/* Add counter */
					count++;
					break;

				case SCEP_PKISTATUS_FAILURE:

					/* Handle failure */
					switch (scep_t.fail_info) {
						case SCEP_FAILINFO_BADALG:
						  exit (SCEP_PKISTATUS_BADALG);
						case SCEP_FAILINFO_BADMSGCHK:
						  exit (SCEP_PKISTATUS_BADMSGCHK);
						case SCEP_FAILINFO_BADREQ:
						  exit (SCEP_PKISTATUS_BADREQ);
						case SCEP_FAILINFO_BADTIME:
						  exit (SCEP_PKISTATUS_BADTIME);
						case SCEP_FAILINFO_BADCERTID:
						  exit (SCEP_PKISTATUS_BADCERTID);
						/* Shouldn't be there... */
						default:
						  exit (SCEP_PKISTATUS_ERROR);
					}
				default:
					fprintf(stderr, "%s: unknown "
						"pkiStatus\n", pname);
					exit (SCEP_PKISTATUS_ERROR);
			}
	}
	/* We got SUCCESS, analyze the reply */
	switch (scep_t.request_type) {

		/* Local certificate */
		case SCEP_REQUEST_PKCSREQ:
		case SCEP_REQUEST_GETCERTINIT:
			write_local_cert(&scep_t);
			break;

		/* Other end entity certificate */
		case SCEP_REQUEST_GETCERT:
			write_other_cert(&scep_t);
			break;

			break;
		/* CRL */
		case SCEP_REQUEST_GETCRL:
			write_crl(&scep_t);
			break;
	}
	//TODO
	//richtiger ort für disable??
//	if(e){
//		ENGINE_finish(*e);
//		ENGINE_free(*e);
//	    hwEngine = NULL;
//	    ENGINE_cleanup();
//	}
//




	return (pkistatus);
}

void
usage() {
	fprintf(stdout, "\nsscep version %s\n\n" , VERSION);
	fprintf(stdout, "Usage: %s OPERATION [OPTIONS]\n"
	"\nAvailable OPERATIONs are\n"
	"  getca             Get CA/RA certificate(s)\n"
	"  getnextca         Get next CA/RA certificate(s)\n"
	"  enroll            Enroll certificate\n"
	"  getcert           Query certificate\n"
	"  getcrl            Query CRL\n"
	"\nGeneral OPTIONS\n"
	"  -u <url>          SCEP server URL\n"
	"  -p <host:port>    Use proxy server at host:port\n"
	"  -M <string>		 Monitor Information String name=value&name=value ...\n"
	"  -g                Enable Engine support\n"
	"  -h				 Keyforme=ID. \n"//TODO
	"  -f <file>         Use configuration file\n"
	"  -c <file>         CA certificate file (write if OPERATION is getca or getnextca)\n"
	"  -E <name>         PKCS#7 encryption algorithm (des|3des|blowfish)\n"
	"  -S <name>         PKCS#7 signature algorithm (md5|sha1)\n"
	"  -v                Verbose operation\n"
	"  -d                Debug (even more verbose operation)\n"
	"\nOPTIONS for OPERATION getca are\n"
	"  -i <string>       CA identifier string\n"
	"  -F <name>         Fingerprint algorithm\n"
	"\nOPTIONS for OPERATION getnextca are\n"
	"  -C <file>         Local certificate chain file for signature verification in PEM format \n"
	"  -F <name>         Fingerprint algorithm\n"
	"  -c <file>         CA certificate file (write if OPERATION is getca or getnextca)\n"
	"  -w <file>         Write signer certificate in file (optional) \n"
	"\nOPTIONS for OPERATION enroll are\n"
 	"  -k <file>         Private key file\n"
	"  -r <file>         Certificate request file\n"
 	"  -K <file>         Signature private key file, use with -O\n"
 	"  -O <file>         Signature certificate (used instead of self-signed)\n"
	"  -l <file>         Write enrolled certificate in file\n"
	"  -e <file>         Use different CA cert for encryption\n"
	"  -L <file>         Write selfsigned certificate in file\n"
	"  -t <secs>         Polling interval in seconds\n"
	"  -T <secs>         Max polling time in seconds\n"
	"  -n <count>        Max number of GetCertInitial requests\n"
 	"  -R                Resume interrupted enrollment\n"
	"\nOPTIONS for OPERATION getcert are\n"
 	"  -k <file>         Private key file\n"
	"  -l <file>         Local certificate file\n"
	"  -s <number>       Certificate serial number\n"
	"  -w <file>         Write certificate in file\n"
	"\nOPTIONS for OPERATION getcrl are\n"
 	"  -k <file>         Private key file\n"
	"  -l <file>         Local certificate file\n"
	"  -w <file>         Write CRL in file\n\n", pname);
	exit(0);
}

void
catchalarm(int signo) {
	fprintf(stderr, "%s: connection timed out\n", pname);
	exit (SCEP_PKISTATUS_TIMEOUT);
}
