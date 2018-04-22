#ifndef GENERALSETTINGS_H
#define GENERALSETTINGS_H

#include <string>

using std::string;

namespace Settings {
	static int rh_port = 22222;
	static string rh_host = "localhost";
	
	static string server_crt = "./private/server.crt"; //certificate for the HTTPS connection between the SP and the App
	static string server_key = "./private/server.key"; //private key for the HTTPS connection

	static string spid = "5E6CCEE07ADF9C31AD6131E0CFA8B52D"; //SPID provided by Intel after registration for the IAS service
	static const char *ias_crt = "./private/client.crt"; //location of the certificate send to Intel when registring for the IAS
	static const char *ias_privkey = "./private/client.key";
	//static string ias_url = "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v1/";
	static string ias_url = "https://test-as.sgx.trustedservices.intel.com:443/attestation/sgx/v2/";
	//the path to sgx_sign ($(SGX_SDK)/SGX_SIGN)
	static string SGX_SIGN = "/bin/x64/sgx_sign";
	static string enclave_signed_so = "../isv_enclave.signed.so";
}

#endif
