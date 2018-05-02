#include <stdlib.h>
#include <stdio.h>
#include <cstdlib>
#include <cassert>
#include <iostream>

#include "Verify.h"
#include "provider.h"
#include "string.h"

int main()
{
	string enclave_signed_so = "../isv_enclave.signed.so";

	uint8_t test_req_pubkey[775]; 

	memset(test_req_pubkey, 1, 775);

	uint8_t quote[1200];
	uint8_t pubkey[775];
	uint8_t sig[512];

	FILE *fp1;
	fp1 = fopen("./data/quote.bin", "rb");
	if(fp1)
	{
		int cnt = fread(quote, 1, 1200, fp1);
		fclose(fp1);
	}else{
		exit(1);
	}

	FILE *fp2;
	fp2 = fopen("./data/pubkey.pem", "rb");
	if(fp2)
	{
		int cnt = fread(pubkey, 1, 1200, fp2);
		fclose(fp1);
	}else{
		exit(1);
	}

	FILE *fp3;
	fp3 = fopen("./data/sig", "rb");
	if(fp3)
	{
		int cnt = fread(sig, 1, 512, fp3);
		fclose(fp1);
	}else{
		exit(1);
	}


	int ret = verify(quote, enclave_signed_so, pubkey, test_req_pubkey,sig);

	printf("verify res: %d\n", ret);

	return 0;	
}

int verify(uint8_t* quote, string enclave_signed_so, uint8_t* pubkey,  uint8_t* req_pubkey, uint8_t* req_pubkey_sig){
	

	if(!verifyQuote(quote)) {
		return VERIFY_QUOTE_FAIL;
	}

	if(!verifyEnclave(quote)){
		return VERIFY_ENCLAVE_FAIL;
	} 	

	if(!verifyPubkey(quote, pubkey)){
		return VERIFY_PUBKEY_FAIL;
	} 	

	if(!verifyReqPubkey(pubkey, req_pubkey, req_pubkey_sig)){
		return VERIFY_REQ_PUBKEY_FAIL;
	} 

	return 0;

}
