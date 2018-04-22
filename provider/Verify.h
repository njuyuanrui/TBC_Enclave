#ifndef VERIFY_H_
#define VERIFY_H_

bool verifyQuote(unsigned char quote[]);

bool verifyEnclave(unsigned char quote[]);

bool verifyPubkey(unsigned char quote[]);

bool verifyReqPubkey();
#endif
