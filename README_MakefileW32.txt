# 2014-20-02 Arkadius Litwinczuk  <arkadius.litwinczuk@gmail.com>
#
#  For the CertNanny sscep project
#
###########How to build sscep with Microsofts Visual Studio C compiler##############

In order to use Microsofts nmake to build a sscep.exe:

1.Install a version of Microsofts Visual studio 8 or higher.

	You can find a free version of Visual Studio express to download at http://www.visualstudio.com/. 
	If you aim to install CertNanny on older systems like Windows 2003 or Windows XP do not use the newest Visual studio
	it doesn't offer the .NET redestributables anylonger for older systems. 

2. Download the latest OpenSSL sources at https://www.openssl.org/

	If you have any reason not to use the latest sources use at least version OpenSSL v1.0.1d.  
	It is required in order to be able to use Private keys located in windows machine keystore.
	SSCEP uses the capi engine which only worked for the User keystore in previouse versions.
	
	A little hint extact the zip file to a directory that doesn't contain spaces in its path, otherwise you 
	will end up having problems following the OpenSSL for Windows compile instructions in INSTALL.W32. 

3. Open a cmd shell and set up the Visual Stutio enviroment with the help of vsvars32.bat. 
	This file is mostly located in C:\Program Files (x86)\Microsoft Visual Studio XXX\Common7\Tools\vsvars32.bat .
	It will setup the required path for nmake , the compiler and the WindowsSDKDir required to build sscep. 

4. Build your OpenSSL and set the enviroment variable for building sscep: 

	e.g.: OpenSSL is located in C:\Temp\openssl-1.0.1f\ after the build it will contain a "\out32dll" directory
	that contains the required liberies to link against from SSCEP. 

	set OPENSSL_SRC=C:\Temp\openssl-1.0.1f\

5. Build SSCEP 
	
	Go to your sscep directory and run: 
	
	nmake -f Makefile.w32 
	
	The resulting output will be located in sscep\out . 

################################### Remarks #########################################

The resulting files are build dynamically and have dependecies to OpenSSL and the .NET C runtime. 

You will need to add the OpenSSL liberies into your SSCEP directory and require to install your 
version of the .NET C runtime depending on the Visual Studio Version you use to build the binary. 



 