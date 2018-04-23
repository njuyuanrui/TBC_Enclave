#ifndef ISV_APP_H_
#define ISV_APP_H_

#include <stdint.h>
#include "isv_type.h"


/**
 * create_enclave： 创建enclave 
 * 
 * 参数：
 * enclave_id: 用于获取enclaveID
 * 
 * 返回值： 0表示创建成功
 */
create_resp_t create_enclave();


/**
 * get_report: 获取report，用于验证enclave启动的正确性
 * 
 * 参数：
 * enclave_id： 指定的enclave的ID
 * spid: 验证方指定的chanllege
 * req_pubkey： 需求方的公钥
 * report: 获取返回的report
 * 
 * 返回值： 0表示成功
 */

report_t get_report( uint64_t enclave_id, uint8_t* spid, uint8_t* req_pubkey);

#endif

