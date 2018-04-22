#include <iostream>
#include <curl/curl.h>
#include <jsoncpp/json/json.h>
#include <string>
#include <vector>

#include "Util/UtilityFunctions.h"
#include "GeneralSettings.h"
#include "WebService.h"
#include "Check.h"

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>

using std::cout;
using std::endl;

bool verifyQuote(unsigned char quote[])
{
	WebService *instance = WebService::getInstance();
	instance->init();

	vector<pair<string, string> > result;
	bool pass_verfication = false;
	pass_verfication = instance->verifyQuote(quote, NULL, NULL, &result);
	if(pass_verfication == false)
	{
		cout << "[Warning]: Cannot pass the verification." << endl;
		exit(-1);
	}

	//tmac: policy here
	for(int i = 0; i < result.size(); ++i)                                     
		cout << "result-" << i << ": " <<result[i].first << " " 
			<< result[i].second << endl;

	return true;
}

bool verifyEnclave(unsigned char quote[])
{
	uint8_t hash[32];
	get_enclave_measurement(Settings::enclave_signed_so, hash);
	bool pass_check = false;
	pass_check = check_measurement(quote, hash);
	if(pass_check == false)
	{
		cout << "[Warning]: The remote enclave has been changed." << endl;
		exit(-1);
	}
	cout << "Enclave hash: ";
	for(int i = 0; i < 32; ++i)
		printf("%x", hash[i]);
	cout << endl << endl;
	return true;
}

bool verifyPubkey(unsigned char quote[])
{
	bool pass_check = check_pubkey(quote, "./data/pubkey.pem");
	if(pass_check == false)
	{
		cout << "[Warning]: The public key has been changed." << endl;
		exit(-1);
	}
	return true;
}



RSA* createRSA(unsigned char *key, int isPublic)
{
    RSA *rsa= NULL;
    BIO *keybio ;
    keybio = BIO_new_mem_buf(key, -1);
    if (keybio==NULL)
    {
        printf( "Failed to create key BIO");
        return 0;
    }
    if(isPublic)
    {
        rsa = PEM_read_bio_RSAPublicKey(keybio, &rsa,NULL, NULL);
    }
    else
    {
        rsa = PEM_read_bio_RSAPrivateKey(keybio, &rsa,NULL, NULL);
    }

    return rsa;
}


bool verifyReqPubkey()
{

	unsigned char req_pubkey[775] = {1};
	memset(req_pubkey, 1, 775);
	unsigned char sig[512];
	unsigned char pubkey[775];
	FILE *fp;
	fp = fopen("./data/sig", "rb");
	if(fp)
	{
		int cnt = fread(sig, 1, 512, fp);
	}
	fclose(fp);

	FILE *fp1;
	fp1 = fopen("./data/pubkey.pem", "rb");
	if(fp1)
	{
		int cnt = fread(pubkey, 1, 775, fp);
	}
	fclose(fp1);
	
	RSA *rsa = createRSA(pubkey,1);
	
	unsigned char req_pubkey_hash[32];
	unsigned char plaintext[32];
    RSA_public_decrypt(512,sig,plaintext,rsa,RSA_PKCS1_PADDING);

	SHA256(req_pubkey, 775, req_pubkey_hash);

	for(int i = 0 ; i < 32 ; ++i ){
		printf("%x", req_pubkey_hash[i]);
	}
	printf("\n");

	for(int i = 0 ; i < 32 ; ++i ){
		printf("%x", plaintext[i]);
	}
	printf("\n");	

	return 0;
	
}

