#include <iostream>
#include <sstream>
#include <string>
#include <fstream>
#include <cassert>
#include <cstdlib>

#include "GeneralSettings.h"

using namespace std;

static int get_enclave_measurement_(string file_path, unsigned char res[32])
{
	fstream fs;
	fs.open(file_path.c_str(), fstream::in);

	string m1, m2;
	string line;
	int find = 0;
	while(getline(fs, line))
	{
		string::size_type found = line.find("enclave_hash");
		if (found != string::npos)
		{
			getline(fs, m1);
			getline(fs, m2);
			find = 1;
			break;
		}
	}
	assert(find == 1);

	stringstream ss;
	ss.str(m1);
	unsigned tmp;
	for(int i = 0; i < 16; ++i)
	{
		ss >> std::hex >> tmp;
		res[i] = (unsigned char)tmp;
	}

	ss.clear();
	ss.str(m2);
	for(int i = 0; i < 16; ++i)
	{
		ss >> std::hex >> tmp;
		res[16+i] = (unsigned char)tmp;
	}

	return 0;
}

//const string SGX_SIGN="/home/tmac/workspace/linux-sgx/linux/installer/bin/sgxsdk/bin/x64/sgx_sign";

/*
 * file_path[in]: enclave.signed.so
 * res[in]: allocated by caller
 */
int get_enclave_measurement(string file_path, unsigned char res[32])
{
	string sgxtool = string(getenv("SGX_SDK"));
	if(sgxtool.empty())
	{
		std::cout << "[error] does not find SGX_SDK variable" << std::endl;
		exit(-1);
	}

	sgxtool += Settings::SGX_SIGN;

	string cmd;
	cmd = sgxtool + " dump -dumpfile .tmp_measurement" + " -enclave " + file_path;
	system(cmd.c_str());
	get_enclave_measurement_(".tmp_measurement", res);
	return 0;
}

#if 0
//test
int main()
{
	unsigned char res[32];
	get_enclave_measurement("../isv_enclave.signed.so", res);
	for(int i = 0; i < 32; ++i)
		cout << hex << (unsigned)res[i] << endl;
	return 0;
}
#endif

