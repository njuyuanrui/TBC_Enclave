#include "Verify.h"
#include "provider.h"


int verify(uint8_t* quote, string enclave_signed_so, uint8_t* pubkey,  uint8_t* req_pubkey, uint8_t* req_pubkey_sig){
	

	if(!verifyQuote(quote)) {
		return VERIFY_QUOTE_FAIL;
	}

	if(!verifyEnclave(quote,enclave_signed_so)){
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
