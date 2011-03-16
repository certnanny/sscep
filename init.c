/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/* Configuration file initialization */

#include "sscep.h"

void
init_config(FILE *conf) {
	char	buff[1024];
	char	*str1, *str2;
	int	k, i, lines;

 	lines = 0;
	while (fgets(buff, 1024, conf)) {
		lines++;

		/* null-terminate: */
		buff[strlen(buff)-1] = '\0'; 

		/* skip leading white space: */
		for ( i = 0 ; isspace(buff[i]) ; i++) 
			;
		
		/* empty line? */
		if (!strlen(&buff[i])) 
			continue;

		/* comment? */
		if (!strncmp("#", &buff[i], 1)) 
			continue;

		/* fetch key and value: */

		k = 0;
		str1 = get_string(&buff[i]);
		i += strlen(&buff[i])+1;
		for ( ; isspace(buff[i]) ; i++ )
			;
		k = 1;
		str2 = get_string(&buff[i]);

		/* if not found... */
		if (!strlen(str2) && v_flag) {
			fprintf(stderr, "%s: config file parse"
					" error, line %d\n", pname, lines);
		/* Parse configuration keys */
		} else {
			if (!strncmp(str1, "CACertFile", 10)) {
				if (!c_flag) {
					c_flag = 1;
					if (!(c_char = strdup(str2))) 
						error_memory();
					}
			} else if (!strncmp(str1, "CAIdentifier", 12)) {
				if (!i_flag) {
					i_flag = 1;
					if (!(i_char = strdup(str2))) 
						error_memory();
					}
			} else if (!strncmp(str1, "CertReqFile", 11)) {
				if (!r_flag) {
					r_flag = 1;
					if (!(r_char = strdup(str2))) 
						error_memory();
					}
			} else if (!strncmp(str1, "Debug", 5)) {
				if (!strncmp(str2, "yes", 3) && !d_flag)
					d_flag = 1;
			} else if (!strncmp(str1, "EncCertFile", 11)) {
				if (!e_flag) {
					e_flag = 1;
					if (!(e_char = strdup(str2)))
						error_memory();
				}
			} else if (!strncmp(str1, "EncAlgorithm", 11)) {
				if (!E_flag) {
					E_flag = 1;
					if (!(E_char = strdup(str2)))
						error_memory();
				}
			} else if (!strncmp(str1, "FingerPrint", 10)) {
				if (!F_flag) {
					F_flag = 1;
					if (!(F_char = strdup(str2)))
						error_memory();
				}
			} else if (!strncmp(str1, "GetCertFile", 11) &&
				(operation_flag == SCEP_OPERATION_GETCERT)) {
				if (!w_flag) {
					w_flag = 1;
					if (!(w_char = strdup(str2))) 
						error_memory();
					}
			} else if (!strncmp(str1, "GetCrlFile", 10) &&
				(operation_flag == SCEP_OPERATION_GETCRL)) {
				if (!w_flag) {
					w_flag = 1;
					if (!(w_char = strdup(str2))) 
						error_memory();
					}
			} else if (!strncmp(str1, "GetCertSerial", 13)) {
				if (!s_flag) {
					s_flag = 1;
					if (!(s_char = strdup(str2))) 
						error_memory();
					}
			} else if (!strncmp(str1, "LocalCertFile", 13)) {
				if (!l_flag) {
					l_flag = 1;
					if (!(l_char = strdup(str2)))
						error_memory();
				}
			} else if (!strncmp(str1, "SignCertFile", 12)) {
				if (!O_flag) {
					O_flag = 1;
					if (!(O_char = strdup(str2)))
						error_memory();
				}
			} else if (!strncmp(str1, "MaxPollCount", 12)) {
				if (!n_flag) {
					n_flag = 1;
					n_num = atoi(str2);
				}
			} else if (!strncmp(str1, "MaxPollTime", 11)) {
				if (!T_flag) {
					T_flag = 1;
					T_num = atoi(str2);
				}
			} else if (!strncmp(str1, "PrivateKeyFile", 15)) {
				if (!k_flag) {
					k_flag = 1;
					if (!(k_char = strdup(str2))) 
						error_memory();
					}
			} else if (!strncmp(str1, "SignKeyFile", 11)) {
				if (!K_flag) {
					K_flag = 1;
					if (!(K_char = strdup(str2))) 
						error_memory();
					}
			} else if (!strncmp(str1, "SelfSignedFile", 15)) {
				if (!L_flag) {
					L_flag = 1;
					if (!(L_char = strdup(str2)))
						error_memory();
				}
			} else if (!strncmp(str1, "SigAlgorithm", 11)) {
				if (!S_flag) {
					S_flag = 1;
					if (!(S_char = strdup(str2)))
						error_memory();
				}
			} else if (!strncmp(str1, "Proxy", 5)) {
				if (!p_flag) {
					p_flag = 1;
					if (!(p_char = strdup(str2)))
						error_memory();
				}
			} else if (!strncmp(str1, "PollInterval", 11)) {
				if (!t_flag) {
					t_flag = 1;
					t_num = atoi(str2);
				}
			} else if (!strncmp(str1, "URL", 3)) {
				if (!u_flag) {
					u_flag = 1;
					if (!(url_char = strdup(str2)))
						error_memory();
				}
			} else if (!strncmp(str1, "Verbose", 7)) {
				if (!strncmp(str2, "yes", 3) && !v_flag)
					v_flag = 1;
			}
		}
	}
}

/* 
 * Find string, strip off '"'s.
 */

char * 
get_string(char *str) {
	char	*tmpstr;
	char	*retstr;
	int	c; 

	/* Malloc space for string: */
	if (!(tmpstr = malloc(strlen(str))))
		error_memory();

	/* check for '"': */
	if (*str != '"') c = 0;
	else c = 1;

	/* not '"': */
	if (!c) {
		retstr = str;
		free(tmpstr);
		while (*str++ != '\0') {
			if (isspace(*str)) {
				break;
			}
		}
		*str = '\0';

	/* starts with '"': */
	} else {
		retstr = tmpstr;
		while  (*str++ != '\0') {
			if (*str == '\\' && *(str+1) && *(str+1) == '"') {
				*tmpstr++ = *(str+1);			
				str++;
			} else if (*str == '"')
				break;
			else
				*tmpstr++ = *str;
		}
		*tmpstr = '\0';
	}
	return retstr;
}

void
error_memory() {
	fprintf(stderr, "%s: memory allocation failure, errno: %d\n",
		pname, errno);
	exit(1);
}

