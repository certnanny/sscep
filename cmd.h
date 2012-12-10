
/*
 * sscep -- Simple SCEP client implementation
 * Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
 * See the file COPYRIGHT for licensing information.
 */

/*
 * Command line options
 * These are defined globally for easy access from all functions.
 * For each command line option 'x', there is int x_flag and
 * char *x_char or int x_num if the option requires parameter.
 */

/* CA certificate */
int c_flag;
char *c_char;

/* CA certificate chain*/
int C_flag;
char *C_char;

/* Debug? */
int d_flag;

/* CA encryption certificate */
int e_flag;
char *e_char;

/* Encryption algorithm */
char *E_char;
int E_flag;

/* Configuration file */
int f_flag;
char *f_char;

/* Fingerprint algorithm */
char *F_char;
int F_flag;

/* enable EnGine support */
char *g_char;
int g_flag;

/* enable hwcrhk keys
 * To set this means that the new key (for which you have the
 * CSR and Private Key) should be taken from the engine
 * while the old key (possibly, see captial letter options)
 * is selected by the -H option
*/
int h_flag;

/* sets if engine should be used if the old key usage is set
 * i.e., setting this uses the old key für signing and does
 * not set anything for the lowercase options that correspond
 * to the new keys
*/
int H_flag;

/* Local certificate  */
char *l_char;
int l_flag;

/* Local selfsigned certificate  (generated automaticatally) */
char *L_char;
int L_flag;

/* CA identifier */
char *i_char;
int i_flag;

/* Private key */
char *k_char;
int k_flag;

/* Private key of already existing certificate */
char *K_char;
int K_flag;

/* Test mode */
int m_flag;
char *m_char;

/* Monitor Information HTTP get parameter style */
int M_flag;
char *M_char;

/* Request count */
int n_flag;
int n_num;

/* Already existing certificate (to be renewed) */
char *O_char;
int O_flag;

/* Proxy */
char *p_char;
int p_flag;

/* GetCrl CRL file */
char *r_char;
int r_flag;

/* Resume */
int R_flag;

/* Certificate serial number */
char *s_char;
int s_flag;

/* Signature algorithm */
char *S_char;
int S_flag;

/* Polling interval */
int t_num;
int t_flag;

/* Max polling time */
int T_num;
int T_flag;

/* URL */
int u_flag;
char *url_char;

/* Verbose? boolean */
int v_flag;

/* GetCert certificate */
int w_flag;
char *w_char;

/* End of command line options */

