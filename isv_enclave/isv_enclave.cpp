/*
 * Copyright (C) 2011-2018 Intel Corporation. All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */


#include <assert.h>
#include <string>
#include "isv_enclave_t.h"
#include "sgx_tkey_exchange.h"
#include "sgx_tcrypto.h"
#include "string.h"

#include "sgx_utils.h"

extern void rsa_key_gen(unsigned char pubkey_hash[], uint8_t* req_pubkey, uint8_t *req_pubkey_sig, uint8_t *enc_pubkey);
extern void printf(char *fmt, ...);
#pragma message ("Default key derivation function is used.")

const std::string MAGIC_NUM = "SJTU_IPADS-UCLOUD: SGX-BLOCKCHAIN";

sgx_status_t tmac_get_report(
	sgx_target_info_t *target_info,
	uint8_t *req_pubkey,
	sgx_report_t *report,
	uint8_t *req_pubkey_sig,
	uint8_t *enc_pubkey)
{

	unsigned char pubkey_hash[32]; //SHA256

	rsa_key_gen(pubkey_hash, req_pubkey, req_pubkey_sig, enc_pubkey);

    sgx_status_t ret;

	sgx_report_data_t report_data; // 64 bytes user-defined
	memset(&report_data, 0, sizeof(sgx_report_data_t));
	
	//64 bytes report_data
	//first part: challenge number or magic number
	for(int i = 0; i < MAGIC_NUM.length(); ++i)
		report_data.d[i] = MAGIC_NUM[i];

	//second part: hash value of the public key
	for(int i = 0; i < 32; ++i)
		report_data.d[i+32] = pubkey_hash[i];

	ret = sgx_create_report(target_info, &report_data, report);

	return ret;
}

