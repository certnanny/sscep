
# SSCEP  -  Simple SCEP client for Unix

> Copyright (c) Jarkko Turkulainen 2003. All rights reserved.
>
> See the file COPYRIGHT for licensing information.


## WHAT IS SSCEP?

SSCEP is a client-only implementation of the SCEP (Cisco System's Simple
Certificate Enrollment Protocol). SSCEP is designed for OpenBSD's isakmpd,
but it will propably work with any Unix system with a recent compiler and
OpenSSL toolkit libraries installed.


## WHAT SCEP?

(From the Cisco Systems White Paper):

SCEP is a PKI communication protocol which leverages existing
technology by using PKCS#7 and PKCS#10.  SCEP is the evolution of the
enrollment protocol developed by Verisign, Inc. for Cisco Systems, Inc.
It now enjoys wide support in both client and CA implementations.

The goal of SCEP is to support the secure issuance of certificates to
network devices in a scalable manner, using existing technology whenever
possible.  The protocol supports the following operations:

  * CA and RA public key distribution
  * Certificate enrollment
  * Certificate and CRL query

Certificate and CRL access can be achieved by using the LDAP protocol,
or by using the query messages defined in SCEP.


## SSCEP FEATURES

Currently, SSCEP implements:
* All of the SCEP operations using SCEP query messages
* HTTP/1.1 queries via IPv4 or IPv6
* Integration with OpenSSL cryptographic engines

There's no LDAP support, and probably there will never be (that's why it is
simple).

SSCEP has been tested successfully against the following CA products:

* [OpenXPKI](https://www.openxpki.org/) (getcaps, getca, enroll and automatic approval works)
* OpenSCEP server (getca, enroll and getcrl works)\*
* Windows2000 server CA + Microsoft SCEP module (works)
* SSH Certifier (getca and enroll works)
* iPlanet CMS (getca and enroll works)\*
* VeriSign Onsite (getca and enroll works)\*\*
* Entrust VPN Connect (getca and enroll works)\*\*\*
* [OpenCA](https://www.openca.org/) (getca, enroll, getcrl and automatic approval works)

> (\*) by default, subjectAltName extensions are dropped from certificate
>
> (\*\*) only DNS subjectAltName allowed (demo mode)
>
> (\*\*\*) demo requires to use /C=US/O=Entrust


## HOW TO COMPILE

The program should compile on the following systems:

* Linux
* OpenBSD
* AIX
* Darwin (PowerPC, no universal binaries yet)
* Tandem NonStop (Guardian), OSS environment, MIPS processor
* z/OS (USS environment)
* Solaris
* Windows

In general, two build systems are supported:

* GNU Autotools (autoconf, automake, libtool)
* CMake

Prerequisites:
* OpenSSL crypto library
  * sscep 0.3.0 - 0.6.1 works with openssl 0.9.7 - 1.0.2
  * sscep 0.7.0 - 0.9.0 works with openssl 0.9.7 - 1.1.1
  * sscep 0.10.0 works with openssl 1.1.0 - 3.0.0

### Unix:

To compile run: 
`$ make`

To generate the configure script when checking out from github source:
```cmd
$ ./bootstrap.sh
```

To compile from a tarball created with 'make dist'
```cmd
$ ./configure
$ make
$ make install
```

To build a RPM package from the tarball do
```cmd
cp sscep-*.tar.gz ~/rpmbuild/SOURCES
rpmbuild -ba scripts/sscep.spec
```

### Windows:

1. Download and install:
   * Microsoft Visual Studio (e.g. the Community Edition) from https://visualstudio.microsoft.com/downloads
   * CMake from https://cmake.org/download
   * Win32/Win64 OpenSSL from http://slproweb.com/products/Win32OpenSSL.html

2. Start the CMake GUI, select *Where is the source code* and *Where to put the binaries*
   (it could be the same), then *Configure* and *Generate* the project files.

3. Start the Visual Studio, open the generated Solution (sscep.sln) and build the project.
   Then copy the sscep binary (Debug or Release) and configuration file sscep.conf somewhere.


### macOS:

Install a few packages from Homebrew:
```cmd
$ brew install autoconf automake libtool pkg-config openssl
```

To generate the configure script when checking out from github source:
```cmd
$ glibtoolize
$ aclocal
$ automake -a -c -f
$ autoreconf
```

Set PKG_CONFIG_PATH and then the usual will work:
```cmd
$ export PKG_CONFIG_PATH="/usr/local/opt/openssl@1.1/lib/pkgconfig"
$ ./configure
$ make
$ make install
```

## HOW TO USE

Running the command "sscep" without any arguments should give you a list
of arguments and command line options.

```bash
$ ./sscep

sscep version 0.9.x

Usage: ./sscep OPERATION [OPTIONS]

Available OPERATIONs are
  getca             Get CA/RA certificate(s)
  enroll            Enroll certificate
  getcert           Query certificate
  getcrl            Query CRL
  getcaps           Query SCEP capabilities

General OPTIONS
  -u <url>          SCEP server URL
  -p <host:port>    Use proxy server at host:port
  -g <engine>       Use the given cryptographic engine
  -f <file>         Use configuration file
  -c <file>         CA certificate file or '-n' suffixed files (write if OPERATION is getca)
  -E <name>         PKCS#7 encryption algorithm (des|3des|blowfish|aes[128]|aes192|aes256)
  -S <name>         PKCS#7 signature algorithm (md5|sha1|sha224|sha256|sha384|sha512)
  -W <secs>         Wait for connectivity, up to <secs> seconds
  -v                Verbose output (for debugging the configuration)
  -d                Debug output (more verbose, for debugging the implementation)

OPTIONS for OPERATION getca are
  -i <string>       CA identifier string
  -F <name>         Fingerprint algorithm (md5|sha1|sha224|sha256|sha384|sha512)

OPTIONS for OPERATION enroll are
  -k <file>         Private key file
  -r <file>         Certificate request file
  -K <file>         Signature private key file, use with -O
  -O <file>         Signature certificate (used instead of self-signed)
  -l <file>         Write enrolled certificate in file
  -e <file>         Use different CA cert for encryption
  -L <file>         Write selfsigned certificate in file
  -t <secs>         Polling interval in seconds
  -T <secs>         Max polling time in seconds
  -n <count>        Max number of GetCertInitial requests
  -R                Resume interrupted enrollment

OPTIONS for OPERATION getcert are
  -k <file>         Signature private key file
  -l <file>         Signature local certificate file
  -s <number>       Certificate serial number (decimal)
  -w <file>         Write certificate in file

OPTIONS for OPERATION getcrl are
  -k <file>         Signature private key file
  -l <file>         Signature local certificate file
  -w <file>         Write CRL in file
```

SSCEP also supports configuration via a configuration file (`-f`).
This is the recommended way to configure SSCEP and all the examples
in below assume that you have done so.

All configuration options are key-value pairs separated with the equal sign
and grouped into sections:

```
[section]
Key = Value
```

Quotation marks are optional - they are needed only if the value contains
space characters (space or tab). Quotation marks inside the value string
must be escaped using a backslash:

```
Key = "Value \"containing quotation marks\""
```

Comment lines (lines starting with '#') and empty lines are discarded.

Here are the available configuration file keys and example values:

| Key	|	Explanation | Example | Command options |
|-------|-------------------|---------|---------|
| URL | URL of the SCEP server. | `http://example.com/scep` | `-u` |
| CACertFile | Sigle CA certificate file, or mutiple CA certificates suffixed with `-0`, `-1`, ... to write (getca) or to choose from (all other operations). | `./ca.crt` |`-c` |
| CAIdentifier | Some CAs require you to define this.  | `mydomain.com` | `-i` |
| CertReqFile | Certificate request file created with mkrequest. | `./local.csr` | `-r`
| EncAlgorithm | PKCS#7 encryption algorithm. Available algorithms are des, 3des, blowfish, aes/aes128, aes192 and aes256. NOTE: SCEP provides no mechanism to "negotiate" the algorithm - even if you send 3des, reply might be des (same thing applies to SigAlgorithm). | | `-E` |
| EncCertFile | If your CA/RA uses a different certificate for encyption and signing, define this. CACertFile is used for verifying the signature. | `./enc.crt` | `-e` |
| SignCertFile | Instead of creating a self-signed certificate from the new key pair use an already existing certficate/key to sign the SCEP request. If the "old" certificate and key is used, the CA can verify that the holder of the private key for an existing certificate re-enrolls for a renewal certificate, allowing for automatic approval of the request. Requires specification of the corresponding SignKeyFile (`-K`). | `./sig.crt` | `-O` |
| SignKeyFile |	See SignCertFile. Specifies the corresponding private key. | `./sig.key` | `-K` |
| FingerPrint | Display fingerprint algorithm. Available algorithms are md5, sha1, sha224, sha256, sha384 and sha512. Default is the best from getcacaps, or md5. || `-F` |
| GetCertFile |  Write certificate asquired via getcert operation. | `./cert.crt` | `-w` |
| GetCertSerial | Certificate serial number. Define this for getcert. The value is defined as a decimal number. | `12` | `-s` |
| GetCrlFile | Write CRL to file. | `./crl.crl` | `-w` |
| LocalCertFile | Write successfully enrolled certificate. | `./local.crt` | `-l` |
| MaxPollCount | Max number of GetCertInitial requests. | `50` | `-n` |
| MaxPollTime | Max polling time in seconds. | `28800` | `-T` |
| PollInterval | Poll periodically for pending certificate. | `60` | `-t` |
| PrivateKeyFile | Private key created with mkrequest. | `./local.key` | `-k` |
| Proxy | Use HTTP proxy at host:port. | `localhost:8080` | `-p` |
| SelfSignedFile | Write optionally the selfsigned certificate in file (needed in SCEP transaction). | `./selfsigned.crt` | `-L` |
| SigAlgorithm | PKCS#7 signature algorithm. Available algorithms are md5, sha1, sha224, sha256, sha384 and sha512. Default is the best from getcacaps, or md5. | | `-S` |
| Verbose | Verbose output? Answer "yes" or "no" | | `-v`|
| Debug | Debug output? Answer "yes" or "no". | | `-d` |

The actual enrollment is done with the following procedure:

### STEP 1 - Gather information

* CA server identification string
If your SCEP server requires you to use a specific identification string
in the initial CA certificate access (step 3), write it down.
* CA server http URL
You must know the *complete* url, with http:// and cgi-program path and
everything. Example: `http://pkiserver.company.com/cgi-bin/pkiclient.exe`
* CA naming policy
You need to know what kind of DN you request. Some may require you to use
unstructuredName naming, some may require a CN with localityName, etc.

### STEP 2 - Make certificate request and key

Before the enrollment can take place, sscep needs a private key file
and the corresponding X.509 certificate request in PKCS#10 format.

This can be created using the mkrequest script, or manually by openssl. Create
an request.cnf, such as:

```
oid_section        = new_oids

[ req ]
default_bits       = 2048
default_keyfile    = local.key
encrypt_key        = no

distinguished_name = req_dn
attributes         = req_attributes
req_extensions     = req_ext

[ new_oids ]
certTemplateName   = 1.3.6.1.4.1.311.20.2

[ req_dn ]
0.domainComponent  = org
1.domainComponent  = OpenXPKI
2.domainComponent  = Test Deployment
commonName         = device

[ req_attributes ]

[ req_ext ]
basicConstraints   = critical, CA:FALSE
keyUsage           = critical, digitalSignature, keyEncipherment
extendedKeyUsage   = serverAuth, clientAuth
subjectAltName     = @alt_names
certTemplateName   = ASN1:UTF8String:pc-client

[ alt_names ]
DNS.1 = www.example.com
DNS.2 = example.com
```

To create a key and a request named local.key and local.csr run:

```bash
$ openssl req -new -config request.cnf -out local.csr
```

You can automate this process using the mkrequest shell script. Edit the DN
variables in the mkrequest file if you need. When ready, make the request:

```bash
$ mkrequest -ip 172.30.0.1
Generating RSA private key, 1024 bit long modulus
..............++++++
...++++++
e is 65537 (0x10001)
Using configuration from .4018client.cnf
```

This also writes key and request named local.key and local.csr (you can change
the "local" with variable PREFIX in mkrequest).

If the CA supports automatic enrollment, you may supply the password in
cert request:

```bash
$ mkrequest -ip 172.30.0.1 password
```


### STEP 3 - Get CA certificate

```bash
$ ./sscep getca -u http://example.com/scep -c ca.crt
./sscep: requesting CA certificate
./sscep: valid response from server
./sscep: MD5 fingerprint: 1D:3C:4C:DF:99:73:B8:FB:B4:EE:C4:56:A9:7C:37:A3
./sscep: CA certificate written as ca.crt
```

NOTE: it is very important to make sure that the CA certificate is really
what you think it is. The security of the whole protocol depends on that!!
This is why the fingerprint is printed on terminal - you should check that
from your CA. You can check the fingerprint any time with command

```bash
$ openssl x509 -in ca.crt -noout -fingerprint
```

If the CA sends a certificate chain, sscep writes all certificates in the
order it founds them in reply and names them with an integer suffix
(-number) appended to CACertFile.

```bash
$ ./sscep getca -u http://example.com/scep -c ca.crt
./sscep: requesting CA certificate
./sscep: valid response from server
./sscep: found certificate with
  subject: /C=FI/O=klake.org/CN=klake.org VPN RA
  issuer: /C=FI/O=klake.org/CN=klake.org VPN CA
  usage: Digital Signature, Non Repudiation
  MD5 fingerprint: 7A:92:84:2A:6F:EE:28:14:F9:69:D8:9D:61:34:B5:67
./sscep: certificate written as ca.crt-0
./sscep: found certificate with
  subject: /C=FI/O=klake.org/CN=klake.org VPN CA
  issuer: /C=FI/O=klake.org/CN=klake.org VPN CA
  usage: Digital Signature, Non Repudiation, Certificate Sign, CRL Sign
  MD5 fingerprint: A5:CE:94:5C:96:77:94:E8:F5:31:AB:D5:31:18:1D:E1
./sscep: certificate written as ca.crt-1
```

SSCEP prints out issuer, subject, key usage and md5/sha1 fingerprint for
each certificate it founds. This information might help you to decide what
certificate to use as `-c` and (optionally) `-e` in subsequent operations.

Some CAs may give you a three (or more) certificates, the root CA(s) plus
different RA certificates for encryption and signing. If that's your case,
you have to define encryption certificate with command line option (`-e`).
Probably it is the certificate with key usage "Key Encipherment".

You may also use the base name (e.g. `ca.crt`) of all certificates and
rely on an automated certificate selection. The system loads all available
certificates (`ca.crt-0`, `ca.crt-1`, ...) and then:
 1. Tries to find a certificate that:
    * Is at the end of the received chain, i.e. do not sign other certificate.
    * Has key usage "Digital Signature" (for `-c`) or "Key Encipherment"
      (for `-e`), or does not have any key usage defined.
 2. If no such key is found, selects the first certificate in the chain, which
    is usually the right certificate anyway.

Currently, SSCEP doesn't verify the CA/RA certificate chain. You can
do it manually with OpenSSL: 

```bash
$ openssl verify -CAfile ca.crt-1 ca.crt-0
ca.crt-0: OK
```

NOTE: In case of multiple CA/RA certificates, the actual CA (the one who
signs your certificate) might not be the same as the CA/RA you are dealing
with. Keep this in mind when installing the CA cert in /etc/isakmpd/ca.


### STEP 4 - Make enrollment

You need to supply URL (`-u`), CACertFile (`-c`), PrivateKeyFile (`-k`),
CertReqFile (`-r`) and output LocalCertFile (`-l`). PrivateKeyFile is the key
generated in step 2 (local.key), CertReqFile is the request (local.csr)
and LocalCertFile is where the enrolled certificate will be written once ready.

If your CA/RA have different certificates for encryption and signing, and you
do not want to use the auto-selection mechanism, you must provide also the
encryption certificate EncCertFile (`-e`).

Normally, the enrollment looks like this:

```bash
$ ./sscep enroll -u http://example.com/scep -c ca.crt -k local.key -r local.csr -l local.crt
./sscep: sending certificate request
./sscep: valid response from server
./sscep: pkistatus: PENDING
./sscep: requesting certificate (#1)
./sscep: valid response from server
./sscep: pkistatus: PENDING
./sscep: requesting certificate (#2)
./sscep: valid response from server
./sscep: pkistatus: PENDING
....
./sscep: requesting certificate (#NNN)
./sscep: valid response from server
./sscep: pkistatus: SUCCESS
./sscep: certificate written as ./local.crt
```

First message sent is PKCSReq, that's where your request goes. Then the CA
writes request down and sends reply PENDING, indicating that the certificate
is not signed yet. SSCEP polls periodically for the certificate by sending
GetCertInitial messages until the CA returns SUCCESS. The polling interval
can be adjusted with PollInterval (`-t`). You can interrupt the process any
time and start again using "sscep enroll ..". You should use the command line
option (`-R`) when you continue (resume) the interrupted enrollment.

If the CA is configured for automatic enrollment (and your request includes
the challenge password), it returns SUCCESS as a first reply. Otherwise, the
enrollment requires manual signing and authentication (perhaps a phone call).


### STEP 5 - Certificate renewal

The SCEP allows to use the existing certificate (issued by the CA) to
authenticate a renewal request. In this context, the SCEP request with the
new public key is signed with the old certificate and key (instead of using
a self-signed certificate created from the new key pair).

If you want to renew the certificate created previously (local.crt), you
follow the enrollment procedure as described before, but supply the current
(old) key and certificate as SignKeyFile (`-K`) and SignCertFile (`-O`).

```bash
$ ./sscep enroll -u http://example.com/scep -c ca.crt -K local.key -O local.crt \
                 -k new.key -r new.csr -l new.crt
```

The actual behaviour of the SCEP server depends on the CA policy and
on the capabilities of the SCEP server (not all servers implement
this feature, using the existing certificate with an older SCEP server
may or may not work, depending on implementation).

Note: For example, [OpenXPKI](https://www.openxpki.org/) is capable of
automatically approving SCEP requests signed with the already existing key pair.


### STEP 6 - Use certificate

Install local.key, local.crt and ca.crt in the isakmpd default locations and
you are ready to go! Default locations are

Private key	/etc/isakmpd/private/local.key
Certificate	/etc/isakmpd/certs/local.crt
CA certificate	/etc/isakmpd/ca/ca.crt

And pay attention to CA certificate if your enrollment was done via RA
server. `openssl verify -CAfile ca.crt local.crt` is your friend here.



### STEP 7 - Check out revocation list (optional)

You need your enrolled certificate for this step.

```bash
$ ./sscep getcrl -f sscep.conf
./sscep: requesting crl
./sscep: valid response from server
./sscep: pkistatus: SUCCESS
./sscep: CRL written as ./crl.crl
```

## CREDITS

I'd like to thank the following people for providing me feedback:

Fiel Cabral,
Manuel Gil Perez


OpenSSL toolkit made this possible.

I would also like to thank OpenSCEP project for it's great software,
reading the source code helped me understand the protocol. Unfortunately,
it's license is too restrictive for my use.

