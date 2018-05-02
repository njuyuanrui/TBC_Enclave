#ifndef PROVIDER_H_
#define PROVIDER_H_

#include <string>
#include <stdint.h>

#define VERIFY_QUOTE_FAIL                  1
#define VERIFY_ENCLAVE_FAIL                2
#define VERIFY_PUBKEY_FAIL                 3
#define VERIFY_REQ_PUBKEY_FAIL             4                 

/*
 *verify：验证quote有效性
 * 
 * 参数：
 * quote： enclave生成的完整quote
 * enclave_signed_so: enclave.signed.so的路径
 * pubkey: enclave公钥
 * req_pubkey: 需求方公钥
 * req_pubkey_sig: enclave提供的需求方公钥签名
 * 
 * 返回值： 
 * 0: 验证成功
 * 1: quote无效
 * 2：enclave代码验证失败
 * 3：pubkey验证失败
 * 4：需求方pubkey验证失败 
 * 
 */ 

int verify(uint8_t* quote, string enclave_signed_so, uint8_t* pubkey,  uint8_t* req_pubkey, uint8_t* req_pubkey_sig);

#endif