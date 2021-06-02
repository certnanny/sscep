
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
extern int c_flag;
extern char *c_char;

/* CA certificate chain*/
extern int C_flag;
extern char *C_char;

/* Debug? */
extern int d_flag;

/* CA encryption certificate */
extern int e_flag;
extern char *e_char;

/* Encryption algorithm */
extern char *E_char;
extern int E_flag;

/* Configuration file */
extern int f_flag;
extern char *f_char;

/* Fingerprint algorithm */
extern char *F_char;
extern int F_flag;

#ifdef WITH_ENGINES
/* enable EnGine support */
extern char *g_char;
extern int g_flag;
#endif

/* enable hwcrhk keys
 * To set this means that the new key (for which you have the
 * CSR and Private Key) should be taken from the engine
 * while the old key (possibly, see captial letter options)
 * is selected by the -H option
*/
extern int h_flag;

/* sets if engine should be used if the old key usage is set
 * i.e., setting this uses the old key for signing and does
 * not set anything for the lowercase options that correspond
 * to the new keys
*/
extern int H_flag;

/* Local certificate  */
extern char *l_char;
extern int l_flag;

/* Local selfsigned certificate  (generated automaticatally) */
extern char *L_char;
extern int L_flag;

/* CA identifier */
extern char *i_char;
extern int i_flag;

/* Private key */
extern char *k_char;
extern int k_flag;

/* Private key of already existing certificate */
extern char *K_char;
extern int K_flag;

/* Test mode */
extern int m_flag;
extern char *m_char;

/* Monitor Information HTTP get parameter style */
extern int M_flag;
extern char *M_char;

/* Request count */
extern int n_flag;
extern int n_num;

/* Already existing certificate (to be renewed) */
extern char *O_char;
extern int O_flag;

/* Proxy */
extern char *p_char;
extern int p_flag;

/* GetCrl CRL file */
extern char *r_char;
extern int r_flag;

/* Resume */
extern int R_flag;

/* Certificate serial number */
extern char *s_char;
extern int s_flag;

/* Signature algorithm */
extern char *S_char;
extern int S_flag;

/* Polling interval */
extern int t_num;
extern int t_flag;

/* Max polling time */
extern int T_num;
extern int T_flag;

/* URL */
extern int u_flag;
extern char *url_char;

/* Verbose? boolean */
extern int v_flag;

/* GetCert certificate */
extern int w_flag;
extern char *w_char;

extern int W_flag;

/* End of command line options */

