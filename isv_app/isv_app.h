#ifndef ISV_APP_H_
#define ISV_APP_H_

#include <stdint.h>

typedef struct _report{
    uint8_t pubkey[775];
    uint16_t quote_size;
    uint8_t quote[1200];
    uint8_t req_pubkey_sig[512];
} report_t;


sgx_enclave_id_t create_enclave();

//void attest_enclave(sgx_enclave_id_t enclave_id);

uint8_t get_report( uint64_t enclave_id, uint8_t* spid, uint8_t* req_pubkey, report_t* report);

#endif

