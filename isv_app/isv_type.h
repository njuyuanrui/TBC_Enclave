#ifndef ISV_TYPE_H_
#define ISV_TYPE_H_

#include <stdint.h>

/**
 * create_resp: 创建enclave时返回结构体
 */
typedef struct _create_resp{
    int8_t   ret;                        // 返回码
    uint64_t enclave_id;                 // enclaveID
} create_resp_t;

// create_enclave 返回码
#define CREATE_ENCLAVE_SUCCESS            0
#define CREATE_ENCLAVE_FAILURE            1


/**
 * report：远程验证时enclave提供的证明
 */
typedef struct _report{
    int8_t   ret;                        // 返回码
    uint8_t  pubkey[775];                // pubkey: enclave生成的公钥
    uint16_t quote_size;                 // quote_size：quote的大小
    uint8_t  quote[1200];                // quote: 包括用于验证enclave身份的信息、运行代码的measurement、enclave公钥的hash以及签名，可以向IAS验证
    uint8_t  req_pubkey_sig[512];        // req_pubkey_sig：利用enclave私钥对需求方公钥签名的值
} report_t;


// get_report 返回码
#define GET_REPORT_SUCCESS                 0
#define INIT_QUOTE_FAILURE                 1
#define CAlC_QUOTE_SIZE_FAILURE            2
#define GET_REPORT_FAILURE                 3
#define GET_QUOTE_FAILURE                  4


#endif