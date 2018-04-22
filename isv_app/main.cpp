#include <stdio.h>
#include "sgx_urts.h"
#include "isv_app.h"
#include "string.h"

int main(int argc, char* argv[])
{
	sgx_enclave_id_t enclave_id = 0;

	enclave_id = create_enclave();
	//attest_enclave(enclave_id);

	uint8_t test_spid[] = { 0x5E, 0x6C, 0xCE, 0xE0, 0x7A, 0xDF, 0x9C, 0x31,
 		0xAD, 0x61, 0x31, 0xE0, 0xCF, 0xA8, 0xB5, 0x2D};

	uint8_t test_req_pubkey[775]; 
	memset(test_req_pubkey, 1, 775);

	report_t report;

	get_report(enclave_id, test_spid, test_req_pubkey, &report);
	sgx_destroy_enclave(enclave_id);
	printf("\nEnter a character before exit ...\n");
	getchar();
	return 0;
}
