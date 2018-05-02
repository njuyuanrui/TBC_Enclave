#ifndef VERIFY_H_
#define VERIFY_H_
#include <stdint.h>

bool verifyQuote(unsigned char quote[]);

bool verifyEnclave(unsigned char quote[],enclave_signed_so);

bool verifyPubkey(unsigned char quote[],unsigned char pubkey[]);

bool verifyReqPubkey(uint8_t* pubkey,  uint8_t* req_pubkey, uint8_t* req_pubkey_sig);
#endif
