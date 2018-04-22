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


#include <stdarg.h>
#include <stdio.h>      /* vsnprintf */
#include <string.h>
//#include <stdlib.h>

//#include <tSgxSSL_api.h>

//#include "Enclave.h"
#include "isv_enclave_t.h"  /* print_string */

#include <openssl/ec.h>    
#include <openssl/bn.h>    
#include <openssl/rsa.h>   
#include <openssl/evp.h>   
#include <openssl/err.h>   
#include <openssl/rand.h>  
#include <openssl/pem.h>

void printf(char *fmt, ...)    
{                                    
	char buf[BUFSIZ] = {'\0'};       
	va_list ap;                      
	va_start(ap, fmt);               
	vsnprintf(buf, BUFSIZ, fmt, ap); 
	va_end(ap);                      
	ocall_print_string(buf);         
}                                    

struct evp_pkey_st {                                 
	int type;                                        
	int save_type;                                   
	int references;                                  
	const EVP_PKEY_ASN1_METHOD *ameth;               
	ENGINE *engine;                                  
	union {                                          
		char *ptr;                                   
# ifndef OPENSSL_NO_RSA                              
		struct rsa_st *rsa;     /* RSA */            
# endif                                              
# ifndef OPENSSL_NO_DSA                              
		struct dsa_st *dsa;     /* DSA */            
# endif                                              
# ifndef OPENSSL_NO_DH                               
		struct dh_st *dh;       /* DH */             
# endif                                              
# ifndef OPENSSL_NO_EC                               
		struct ec_key_st *ec;   /* ECC */            
# endif                                              
	} pkey;                                          
	int save_parameters;                             
	STACK_OF(X509_ATTRIBUTE) *attributes; /* [ 0 ] */
	CRYPTO_RWLOCK *lock;                             
} /* EVP_PKEY */ ;                                   

#pragma GCC diagnostic ignored "-Wwrite-strings"

//global data RSA key pair
RSA *keypair = NULL;

//pubkey_hash'size is 32 (sha256)
void rsa_key_gen(unsigned char pubkey_hash[], uint8_t* req_pubkey, uint8_t *req_pubkey_sig)
{                                                                      
	BIGNUM *bn = BN_new();                                             
	if (bn == NULL) {                                                  
		printf("BN_new failure: %ld\n", ERR_get_error());              
		return;                                                        
	}                                                                  
	int ret = BN_set_word(bn, RSA_F4);                                 
	if (!ret) {                                                        
		printf("BN_set_word failure\n");                               
		return;                                                        
	}                                                                  

	keypair = RSA_new();                                          
	if (keypair == NULL) {                                             
		printf("RSA_new failure: %ld\n", ERR_get_error());             
		return;                                                        
	}                                                                  
	ret = RSA_generate_key_ex(keypair, 4096, bn, NULL);                
	//ret = RSA_generate_key_ex(keypair, 1024, bn, NULL);                
	if (!ret) {                                                        
		printf("RSA_generate_key_ex failure: %ld\n", ERR_get_error()); 
		return;                                                        
	}                                                                  

//test: RSA encryption/decryption
#if 0
	//static const char rnd_seed[] = "asdfdasgdsafcadsgasdffasdgdsagdasgadsgdasgdsagsad";
	//RAND_seed(rnd_seed, sizeof(rnd_seed));

	unsigned char *ptext = (unsigned char*)"12345678";
	//unsigned char *ptext = (unsigned char*)malloc(4096);
	int plen = sizeof(ptext);
	//unsigned char* ctext = (unsigned char*)malloc(16);
	//unsigned char* pres = (unsigned char*)malloc(16);
	unsigned char* ctext = (unsigned char*)malloc(4096);
	unsigned char* pres = (unsigned char*)malloc(4096);
	//memset(ptext, 0, 4096);
	memset(ctext, 0, 4096);
	memset(pres, 0, 4096);
	//for(int i = 0; i < 8; ++i)
	//	ptext[i] = '1' + i;
	printf("plen: %d\n", plen);
	int num = RSA_public_encrypt(plen, ptext, ctext, keypair, RSA_PKCS1_PADDING);
	printf("RSA_public_encrypt return encrypt length: %d\n", num);
	num = RSA_private_decrypt(num, ctext, pres, keypair, RSA_PKCS1_PADDING);
	printf("decrypt res: %s\n", pres);
#endif

#if 0
	EVP_PKEY *evp_pkey = EVP_PKEY_new();                               
	if (evp_pkey == NULL) {                                            
		printf("EVP_PKEY_new failure: %ld\n", ERR_get_error());        
		return;                                                        
	}                                                                  
	EVP_PKEY_assign_RSA(evp_pkey, keypair);                            
	// public key - string                                             
	int len = i2d_PublicKey(evp_pkey, NULL);                           
	unsigned char *buf = (unsigned char *) malloc (len + 1);           
	unsigned char *tbuf = buf;                                         
	i2d_PublicKey(evp_pkey, &tbuf);                                    
	free(buf);                                                         
#endif
	
	/* To get the C-string PEM form: */
	BIO *bio = BIO_new(BIO_s_mem());
	if(bio == NULL) printf("BIO failed\n");
	//PEM_write_bio_PKCS8PrivateKey(bio, evp_pkey, NULL, NULL, 0, NULL, NULL);
	PEM_write_bio_RSAPublicKey(bio, keypair);


	int keylen = BIO_pending(bio);
	char *pem_key = (char*)calloc(keylen+1, 1); /* Null-terminate */
	BIO_read(bio, pem_key, keylen);

	ocall_print_pubkey(pem_key);
	printf("[tmac] sha256 public key length %d\n", keylen);
	sgx_status_t status = sgx_sha256_msg((const uint8_t *)pem_key, keylen,
			(sgx_sha256_hash_t *)pubkey_hash);
	if(status != SGX_SUCCESS)
		printf("[tmac] sgx_sha256_msg failed, status: %d\n", status);


	uint8_t req_pubkey_hash[32];
	status = sgx_sha256_msg((const uint8_t *)req_pubkey, 775,
			(sgx_sha256_hash_t *)req_pubkey_hash);

	if(status != SGX_SUCCESS)
		printf("[tmac] sgx_sha256_msg failed, status: %d\n", status);


	for(int i = 0 ; i < 32 ; ++i ){
		printf("%x", req_pubkey_hash[i]);
	}
	printf("\n");

	uint8_t req_pubkey_sig1[512];
	
	int cipper_len = -1;
	cipper_len = RSA_private_encrypt(32, req_pubkey_hash, req_pubkey_sig, keypair, RSA_PKCS1_PADDING);
	if(cipper_len < 0){
		printf("signature req_pubkey failed\n");
	}else{
		printf("signature succeed: %d \n", cipper_len);
		
		uint8_t plaintext[512];
		int plantex_len = RSA_public_decrypt(cipper_len, req_pubkey_sig, plaintext, keypair, RSA_PKCS1_PADDING);

		
		printf("decrypt succeed: %d\n", plantex_len);

		for(int i = 0 ; i < 32 ; ++i ){
			printf("%x", plaintext[i]);
		}
		printf("\n");
	}

	

#if 0
	// private key - string                                            
	len = i2d_PrivateKey(evp_pkey, NULL);                              
	buf = (unsigned char *) malloc (len + 1);                          
	tbuf = buf;                                                        
	i2d_PrivateKey(evp_pkey, &tbuf);                                   

	bio = BIO_new(BIO_s_mem());
	if(bio == NULL) printf("BIO failed\n");
	PEM_write_bio_PKCS8PrivateKey(bio, evp_pkey, NULL, NULL, 0, NULL, NULL);
	keylen = BIO_pending(bio);
	pem_key = (char*)calloc(keylen+1, 1); /* Null-terminate */
	BIO_read(bio, pem_key, keylen);
	//printf("%s", pem_key);

	free(buf);                                                         
	BN_free(bn);                                                       
	EVP_PKEY_free(evp_pkey);           
	//if (evp_pkey->pkey.ptr != NULL) {  
	//	RSA_free(keypair);               
	//}                                  
#endif
}
#pragma GCC diagnostic pop

