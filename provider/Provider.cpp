#include <cstdlib>
#include <cassert>
#include <iostream>

#include "Verify.h"

int main()
{
	// FILE *fp;
	// fp = fopen("./data/quote.bin", "rb");
	// if(fp)
	// {
	// 	unsigned char quote[1200];
	// 	int cnt = fread(quote, 1, 1200, fp);
	// 	//assert(cnt == 1116);

	// 	assert(verifyQuote(quote) == true);
	// 	assert(verifyEnclave(quote) == true);
	// 	assert(verifyPubkey(quote) == true);
	// 	//assert(verifyrReqPubkey(quote) == true);

	// 	std::cout << "[Final Result]: Correct enclave and public key!" 
	// 		<< std::endl;
	// }
	// else
	// 	std::cout << "[failed]: Cannot find ./data/quote.bin from the remote enclave." 
	// 		<< std::endl;
	verifyReqPubkey();
	return 0;	
}
