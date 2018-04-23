#include <stdio.h>
#include "isv_app.h"
#include "string.h"
#include <stdint.h>

int main(int argc, char* argv[])
{
	uint64_t enclave_id ;

	create_resp_t create_resp = create_enclave();

	if(CREATE_ENCLAVE_SUCCESS != create_resp.ret){
		printf("create enclave fail! \n");
		exit(1);
	}

	enclave_id = create_resp.enclave_id;

	//=========================构造测试输入==================================
	uint8_t test_spid[] = { 0x5E, 0x6C, 0xCE, 0xE0, 0x7A, 0xDF, 0x9C, 0x31,
 		0xAD, 0x61, 0x31, 0xE0, 0xCF, 0xA8, 0xB5, 0x2D};
	uint8_t test_req_pubkey[775]; 
	memset(test_req_pubkey, 1, 775);
	//======================================================================


	report_t report = get_report(enclave_id, test_spid, test_req_pubkey);

	if(GET_REPORT_SUCCESS != report.ret){
		printf("get report fail! \n");
		destroy_enclave(enclave_id);
		exit(1);
	}

	destroy_enclave(enclave_id);
	printf("\nEnter a character before exit ...\n");
	getchar();
	return 0;
}
