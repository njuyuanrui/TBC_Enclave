#include <cstdlib>
#include <cstdio>
#include <iostream>
#include <sstream>
#include <memory>
#include <stdexcept>
#include <string>

using std::string;

//report's offset in quote is 48
static const int ENCLAVE_HASH_OFFSET = 48 + 64;
static const int ENCLAVE_HASH_SIZE = 32;

//report's offset in quote is 48
//user_data's offset in report is 320
//the first part is magic number or challenger (32)
//the second part is pubkey hash (32)
static const int PUBKEY_HASH_OFFSET = 48 + 320 + 32;
static const int PUBKEY_HASH_SIZE = 32;

static string exec(const char* cmd) {
	char buffer[128];
	std::string result = "";
	FILE* pipe = popen(cmd, "r");
	if (!pipe) throw std::runtime_error("popen() failed!");
	try {
		while (!feof(pipe)) {
			if (fgets(buffer, 128, pipe) != NULL)
				result += buffer;
		}
	} catch (...) {
		pclose(pipe);
		throw;
	}
	pclose(pipe);
	return result;
}

bool check_measurement(unsigned char quote[], unsigned char hash[])
{
	for(int i = 0; i < ENCLAVE_HASH_SIZE; ++i)
		if(quote[ENCLAVE_HASH_OFFSET+i] != hash[i])
			return false;
	return true;
}

bool check_pubkey(unsigned char quote[], string pubkey_file)
{
	string cmd;	
	cmd = "sha256sum " + pubkey_file;
	//system(cmd.c_str());
	string res = exec(cmd.c_str());
	std::cout << res << std::endl;

	for(int i = 0; i < PUBKEY_HASH_SIZE; ++i)
	{
		string str = "0x"+res.substr(i*2, 2);
		unsigned tmp;
		std::stringstream ss;
		ss.str(str);
		ss >> std::hex >> tmp;
		//std::cout << tmp << std::endl;
		if(tmp != quote[PUBKEY_HASH_OFFSET+i])
			return false;
	}
	return true;
}
