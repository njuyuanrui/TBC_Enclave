
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


#define _T(x) x
create_resp_t create_enclave()
{
	create_resp_t resp;

	sgx_status_t ret;                                                         
	sgx_enclave_id_t sgx_enclave_id = 0;

	FILE* OUTPUT = stdout;

	// creates the worker enclave
	int launch_token_update = 0;
	sgx_launch_token_t launch_token = {0};
	memset(&launch_token, 0, sizeof(sgx_launch_token_t));

	ret = sgx_create_enclave(_T(ENCLAVE_PATH),
			SGX_DEBUG_FLAG,
			&launch_token,
			&launch_token_update,
			&sgx_enclave_id, NULL);
	if(SGX_SUCCESS != ret)
	{
		fprintf(OUTPUT, "\nError, call sgx_create_enclave fail [%s].",
				__FUNCTION__);
		sgx_destroy_enclave(sgx_enclave_id);
		resp.ret = CREATE_ENCLAVE_FAILURE;
		return resp;
	}
	fprintf(OUTPUT, "\nCall sgx_create_enclave success.\n");
	
	resp.enclave_id = (uint64_t)sgx_enclave_id;

	return resp;
}



report_t get_report(uint64_t enclave_id, uint8_t* spid, uint8_t* req_pubkey){

	report_t report;

	sgx_status_t ret;                                                         
	sgx_status_t status = SGX_SUCCESS;
	
	// retrieve the attestation report
	sgx_target_info_t p_target_info;                                          
	sgx_epid_group_id_t p_gid;                                                

	ret = sgx_init_quote(&p_target_info, &p_gid);                             
	
	if(SGX_SUCCESS != ret) {
		printf("init quote fail! ret: %d \n", ret);
		report.ret = INIT_QUOTE_FAILURE;
		return report;
	}

	uint32_t p_quote_size;
	ret = sgx_calc_quote_size(NULL, 0, &p_quote_size);

	if(SGX_SUCCESS != ret) {
		printf("calculate quote size fail! ret: %d \n" , ret);
		report.ret = CAlC_QUOTE_SIZE_FAILURE;
		return report;
	}

	report->quote_size = p_quote_size;

	sgx_report_t sgx_report;


	ret = tmac_get_report((sgx_enclave_id_t)enclave_id, &status, &p_target_info, req_pubkey, &sgx_report, report.req_pubkey_sig, report.pubkey);

	if(SGX_SUCCESS != ret){
		printf("get report fail! ret: %d \n" , ret);
		report.ret = GET_REPORT_FAILURE;
		return report;
	}


	//==================================get quote============================================
	sgx_spid_t sgx_spid; 
	sgx_quote_t *quote = (sgx_quote_t*)malloc(p_quote_size);
	
	printf("quote size: %d \n", p_quote_size);
	for(int i = 0; i < 16; ++i)
		sgx_spid.id[i] = spid[i];

	ret = sgx_get_quote(&sgx_report, SGX_UNLINKABLE_SIGNATURE, &sgx_spid, NULL, NULL, 
			0, NULL, quote, p_quote_size);
	

	if(SGX_SUCCESS != ret){
		printf("get quote fail! ret: %d \n" , ret);
		report.ret = GET_QUOTE_FAILURE;
		return report;
	}

	strncpy((char*)report.quote, (const char*)quote, p_quote_size);

	//==============for test=====================
	FILE *fp;
	fp = fopen("./provider/data/quote.bin", "w+b");
	fwrite((void*)quote, p_quote_size, 1, fp);
	fclose(fp);

	FILE *fp1;
	fp1 = fopen("./provider/data/sig", "w+b");
	fwrite((void*)report->req_pubkey_sig, 512, 1, fp1);
	fclose(fp1);
	//============================================
	report.ret = GET_REPORT_SUCCESS;
	return report;

}