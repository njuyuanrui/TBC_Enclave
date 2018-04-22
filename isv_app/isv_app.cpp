
#include <stdio.h>
#include <limits.h>
#include <unistd.h>

#include "isv_enclave_u.h"

// Needed to create enclave and do ecall.
#include "sgx_urts.h"
// Needed to query extended epid group id.
#include "sgx_uae_service.h"
#include "isv_app.h"


#define ENCLAVE_PATH "isv_enclave.signed.so"

void ocall_print_string(const char* str)
{
	printf("%s", str);
}

void ocall_print_pubkey(const char* pubkey)
{
	//printf("%s\n", pubkey);
	FILE *fp;
	fp = fopen("./provider/data/pubkey.pem", "w+b");
	if(fp == NULL) 
		printf("Cannot open ./provider/data/pubkey.pem");
	fwrite(pubkey, strlen(pubkey), 1, fp);
	fclose(fp);
}

//debug
#if 0
void tmac_print_quote(sgx_quote_t *quote)
{
	printf("version: %d\n", quote->version);
	printf("sign type: %d\n", quote->sign_type);
	printf("epid_group_id: %x %x %x %x\n", quote->epid_group_id[0], 
			 quote->epid_group_id[1],  quote->epid_group_id[2],  quote->epid_group_id[3]);

	for(int i = 0; i < 4; ++i)
		printf("report_data[%d]: %c, ", i, quote->report_body.report_data.d[i]);
	printf("\n");
	printf("signature length: %d\n", quote->signature_len);
	for(int i = 0; i < 4; ++i)
		printf("signature[%d]: %x, ", i, quote->signature[i]);
	printf("\n");

	for(int i = 0; i < 32; ++i)
		printf("enclave_hash[%d]: 0x%x\n", i, quote->report_body.mr_enclave.m[i]);
}
#endif

#define _T(x) x
sgx_enclave_id_t create_enclave()
{
	sgx_status_t ret;                                                         
	sgx_status_t status = SGX_SUCCESS;
	sgx_enclave_id_t enclave_id = 0;
	//int enclave_lost_retry_time = 1;
	FILE* OUTPUT = stdout;

	//uint32_t extended_epid_group_id = 0;
	//ret = sgx_get_extended_epid_group_id(&extended_epid_group_id);

	// creates the worker enclave
	int launch_token_update = 0;
	sgx_launch_token_t launch_token = {0};
	memset(&launch_token, 0, sizeof(sgx_launch_token_t));

	ret = sgx_create_enclave(_T(ENCLAVE_PATH),
			SGX_DEBUG_FLAG,
			&launch_token,
			&launch_token_update,
			&enclave_id, NULL);
	if(SGX_SUCCESS != ret)
	{
		fprintf(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
				__FUNCTION__);
		sgx_destroy_enclave(enclave_id);
		exit(-1);
	}
	fprintf(OUTPUT, "\nCall sgx_create_enclave success.\n");
	
	return enclave_id;
}

// void attest_enclave(sgx_enclave_id_t enclave_id)
// {
// 	sgx_status_t ret;                                                         
// 	sgx_status_t status = SGX_SUCCESS;
	
// 	// retrieve the attestation report
// 	sgx_target_info_t p_target_info;                                          
// 	sgx_epid_group_id_t p_gid;                                                

// 	ret = sgx_init_quote(&p_target_info, &p_gid);                             
// 	printf("[tmac] sgx_init_quote return %d, SGX_SUCCESS is %d\n", ret, SGX_SUCCESS);

// 	uint32_t p_quote_size;
// 	//ret = sgx_get_quote_size(NULL, &p_quote_size);
// 	ret = sgx_calc_quote_size(NULL, 0, &p_quote_size);
// 	printf("[tmac] sgx_calc_quote_size return %d, size %d\n", ret, p_quote_size);

// 	sgx_report_t report;
// 	ret = tmac_get_report(enclave_id, &status, &p_target_info, &report);
// 	printf("[tmac] tmac_get_report return ret %d, status %d\n", ret, status);

// 	//TODO read SPID
// 	// get the spid from the blockchain (as part of challenge)
// 	sgx_spid_t spid; //5E 6C CE E0 7A DF 9C 31 AD 61 31 E0 CF A8 B5 2D
// 	sgx_quote_t *quote = (sgx_quote_t*)malloc(p_quote_size);

// 	uint8_t tmac_spid[] = { 0x5E, 0x6C, 0xCE, 0xE0, 0x7A, 0xDF, 0x9C, 0x31,
// 		0xAD, 0x61, 0x31, 0xE0, 0xCF, 0xA8, 0xB5, 0x2D};
// 	for(int i = 0; i < 16; ++i)
// 		spid.id[i] = tmac_spid[i];
// 	ret = sgx_get_quote(&report, SGX_UNLINKABLE_SIGNATURE, &spid, NULL, NULL, 
// 			0, NULL, quote, p_quote_size);
// 	printf("[tmac] sgx_get_quote return %d\n", ret);

// 	if(ret == 0)
// 		printf("[tmac] Success: get quote and pubkey of enclave"
// 				" [execute \'ls ./provider/data/\']\n");

// 	FILE *fp;
// 	fp = fopen("./provider/data/quote.bin", "w+b");
// 	fwrite((void*)quote, p_quote_size, 1, fp);
// 	fclose(fp);
// }



uint8_t get_report(uint64_t enclave_id, uint8_t* spid, uint8_t* req_pubkey, report_t* report){

	sgx_status_t ret;                                                         
	sgx_status_t status = SGX_SUCCESS;
	
	// retrieve the attestation report
	sgx_target_info_t p_target_info;                                          
	sgx_epid_group_id_t p_gid;                                                

	ret = sgx_init_quote(&p_target_info, &p_gid);                             

	uint32_t p_quote_size;
	ret = sgx_calc_quote_size(NULL, 0, &p_quote_size);

	sgx_report_t sgx_report;
	uint8_t req_pubkey_sig[512];

	ret = tmac_get_report((sgx_enclave_id_t)enclave_id, &status, &p_target_info, req_pubkey, &sgx_report, req_pubkey_sig);

	sgx_spid_t sgx_spid; 
	sgx_quote_t *quote = (sgx_quote_t*)malloc(p_quote_size);
	
	for(int i = 0; i < 16; ++i)
		sgx_spid.id[i] = spid[i];

	ret = sgx_get_quote(&sgx_report, SGX_UNLINKABLE_SIGNATURE, &sgx_spid, NULL, NULL, 
			0, NULL, quote, p_quote_size);
	printf("[tmac] sgx_get_quote return %d\n", ret);

	if(ret == 0)
		printf("[tmac] Success: get quote and pubkey of enclave"
				" [execute \'ls ./provider/data/\']\n");

	FILE *fp;
	fp = fopen("./provider/data/quote.bin", "w+b");
	fwrite((void*)quote, p_quote_size, 1, fp);
	fclose(fp);

	return 0;


}