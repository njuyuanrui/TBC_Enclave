#include <iostream>
#include <curl/curl.h>
#include <jsoncpp/json/json.h>
#include <string>
#include <vector>

#include "Util/UtilityFunctions.h"
#include "GeneralSettings.h"
#include "WebService.h"
#include "Check.h"

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
