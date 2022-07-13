// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

/* Copyright (c) 2021 SUSTech University
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "crypto.h"
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <string.h>
#include <chrono>


Crypto::Crypto()
{
    m_crypto_initialized = init_openssl();
}

Crypto::~Crypto()
{
    cleanup_openssl();
}

//INFO Print time for function runtime
int64_t print_time2()
{

  std::chrono::milliseconds ms = std::chrono::duration_cast< std::chrono::milliseconds >(
      std::chrono::system_clock::now().time_since_epoch()
  );
  return ms.count();  
}

/**
 * @brief init crypto object including initialization of ecdsa、aes、rsa、hash
 * @return true
 * @return false
 */
int Crypto::init_openssl(void)
{
    //implement openssl 
    int ret = 1;
    rsa = RSA_new();
    e = BN_new();
    BN_set_word(e, 17);
    gencb = NULL;
    pkey = EVP_PKEY_new();
    ret = RSA_generate_key_ex(rsa, 2048, e, gencb);
    ret = EVP_PKEY_set1_RSA(pkey, rsa);
    if(ret == 0)
    {
        TRACE_ENCLAVE("OpenSsl Generate RSA Key failed.");
        goto exit;
    }
    out = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSA_PUBKEY(out,rsa);//take rsa pubkey
    if(ret == 0){ // PEM_write_bio_RSA_PUBKEY return 1 representation successful
        TRACE_ENCLAVE("ECDSA Step failed.PEM_write_bio_EC_PUBKEY Failed");
        goto exit;
    }
    swap_pp_size = BIO_read(out,swap_pp,BIO_get_mem_data(out,nullptr));//NID_secp192k1 ecdsa length is 150
    if(swap_pp_size == 0) // If the result is 0 or -1, the read fails
    {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        goto exit;
    }
    memcpy(m_rsa_public_key,swap_pp,sizeof(m_rsa_public_key));
    memset(swap_pp,0,sizeof(swap_pp));
    ret = BIO_reset(out);//reset out BIO
    if(ret != 1)
    {
        TRACE_ENCLAVE("ECDSA Step BIO reset failed.");
        goto exit;
    }
    ret = PEM_write_bio_RSAPrivateKey(out,rsa,0,0,0,0,0);
    if(ret == 0){ // PEM_write_bio_RSA_PUBKEY return 1 representation successful
        TRACE_ENCLAVE("ECDSA Step failed.PEM_write_bio_EC_PUBKEY Failed");
        goto exit;
    }
    swap_pp_size = BIO_read(out,swap_pp,BIO_get_mem_data(out,nullptr));//NID_secp192k1 ecdsa length is 150
    if(swap_pp_size == 0) // If the result is 0 or -1, the read fails
    {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        goto exit;
    }
    memcpy(m_rsa_private_key,swap_pp,sizeof(m_rsa_private_key));//distill the private key
    memset(swap_pp,0,sizeof(swap_pp));
    ret = BIO_reset(out);//reset out BIO
    if(ret != 1)
    {
        TRACE_ENCLAVE("ECDSA Step BIO reset failed.");
        goto exit;
    }
    TRACE_ENCLAVE("OpenSsl RSA step init Successful!");
    //AES Openssl implement
    //Genc a aes key
    bn = BN_new();
    BN_rand(bn,  AES_BLOCK_SIZE * 8, -1, 1); //genc 128 bit random 
    memcpy(m_aes_key,BN_bn2hex(bn), AES_BLOCK_SIZE * 8);
    BN_free(bn);//Free bignum
    TRACE_ENCLAVE("AES Key is %s",m_aes_key);
    if(AES_set_encrypt_key(m_aes_key,  AES_BLOCK_SIZE * 8, &AesKey) < 0)
    {
        TRACE_ENCLAVE("AES_set_encrypt_key failed");
        goto exit;
    }
    TRACE_ENCLAVE("OpenSsl AES step init Successful!");
    //INIT Ecdsa
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); //Choose ecdsa curve
    if(eckey == NULL){
        TRACE_ENCLAVE("ECDSA Step failed. EC_KEY_new_by_curve_name Failed");
        goto exit;
    }
    if(!EC_KEY_generate_key(eckey)){   // Genc the ec key 
        TRACE_ENCLAVE("ECDSA Step failed.EC_KEY_generate_key Failed");
        goto exit;
    }
    //extract ECDSA public key
    // out = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_EC_PUBKEY(out,eckey);
    if(ret == 0){ // PEM_write_bio_EC_PUBKEY return 1 representation successful
        TRACE_ENCLAVE("ECDSA Step failed.PEM_write_bio_EC_PUBKEY Failed");
        goto exit;
    }
    swap_pp_size = BIO_read(out,swap_pp,BIO_get_mem_data(out,nullptr));//NID_secp192k1 ecdsa length is 150
    // TRACE_ENCLAVE("ECDSA Step failed.BIO new %d  %s",ret,swap_pp);
    if(swap_pp_size == 0) // If the result is 0 or -1, the read fails
    {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        goto exit;
    }
    memcpy(m_ecdsa_public_key,swap_pp,sizeof(m_ecdsa_public_key));//distill the private key
    memset(swap_pp,0,sizeof(swap_pp));
    ret = BIO_reset(out);//reset out BIO
    if(ret != 1)
    {
        TRACE_ENCLAVE("ECDSA Step BIO reset failed.");
        goto exit;
    }
    ret = PEM_write_bio_ECPrivateKey(out,eckey,NULL, NULL, 0, NULL, NULL);// ecdsa private key
    swap_pp_size = BIO_read(out,swap_pp,BIO_get_mem_data(out,nullptr));//NID_secp192k1 ecdsa length is 150
    if(swap_pp_size == 0) // If the result is 0 or -1, the read fails
    {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        goto exit;
    }
    memcpy(m_ecdsa_private_key,swap_pp,sizeof(m_ecdsa_private_key));//distill the private key
    memset(swap_pp,0,sizeof(swap_pp));
    ret = BIO_reset(out);//reset out BIO
    TRACE_ENCLAVE("OpenSsl ECDSA step init Successful!");
    ret = 0;
    TRACE_ENCLAVE("Openssl initialized.");
exit:
    return ret;
}

void Crypto::cleanup_openssl(void)
{
    //TODO clean function
    TRACE_ENCLAVE("openssl cleaned up.");
}




// Compute the sha256 hash of given data.
int Crypto::Sha256(const uint8_t *data, size_t data_size, uint8_t sha256[32])
{
    int ret = 0;
    if (SHA256((unsigned char*)data, data_size, sha256) == NULL) {
		TRACE_ENCLAVE("sha256 erro\n");
        ret = 1;
		goto exit;
	}
exit:
    return ret;
}


/**
 * @brief Use RSA key to encrypt data
 * @param pem_public_key rsa public key
 * @param data
 * @param data_size
 * @param encrypted_data
 * @param encrypted_data_size
 */
int Crypto::rsa_encrypt(
    uint8_t *pem_public_key,
    size_t pem_public_key_size,
    const uint8_t *data,
    size_t data_size,
    uint8_t *encrypted_data,
    size_t *encrypted_data_size)
{
    int ret = 1;
    RSA *rsa_recover = RSA_new();;
    BIO *temp = NULL;
    int encrypt_len = 0;
    long swap_size = 0;
    int padding = RSA_PKCS1_PADDING;
    char swap_buffer[1024] = "";
    unsigned char* rsa_out;

    if (m_crypto_initialized != 0)//If init failed can not continue
        goto exit;
    temp = BIO_new(BIO_s_mem());
    memcpy(swap_buffer,pem_public_key,pem_public_key_size);
    TRACE_ENCLAVE("PK %d IS %s",pem_public_key_size,m_rsa_public_key);
    BIO_printf(temp, swap_buffer);
    if(temp == NULL){
        TRACE_ENCLAVE("Failed to BIO_new_mem_buf!");
        goto exit;
    }
    rsa_recover = PEM_read_bio_RSA_PUBKEY(temp, NULL, NULL, NULL); // Read public from BIO memory
    if (rsa_recover == NULL){
        TRACE_ENCLAVE("RSA Read public key failed.");
        goto exit;
    }
    TRACE_ENCLAVE("Start!RSA_public_encrypt Start!.Time is %d",print_time2());
    encrypt_len = RSA_size(rsa_recover);
    rsa_out = (unsigned char*)malloc(encrypt_len);
    ret = RSA_public_encrypt((int)data_size, data, rsa_out, rsa_recover, padding);
    if (ret <= 0){
        TRACE_ENCLAVE("RSA Step Failed.RSA_public_encrypt failed!.");
        goto exit;
    }
    TRACE_ENCLAVE("Finish!RSA_public_encrypt Successful!.Time is %d",print_time2());

    memcpy(encrypted_data,rsa_out,encrypt_len);
    *encrypted_data_size = encrypt_len;
    TRACE_ENCLAVE("Finish!RSA_public_encrypt Successful!.Time is %d",print_time2());
    if (PRINT_CRYPTO_MESSAGE)
    {
        TRACE_ENCLAVE("Rsa Encrypt message succeed.");
    }
    ret = 0;
exit:
    //TODO Free something
    return ret;
}

/**
 * @brief rsa decrypt data
 * @param encrypted_data
 * @param encrypted_data_size
 * @param data
 * @param data_size
 */
int Crypto::rsa_decrypt(
    const uint8_t *encrypted_data,
    size_t encrypted_data_size,
    uint8_t *data,
    size_t *data_size)
{
    int ret = 1;
    BIO *temp = NULL;
    int encrypt_len = 0;
    long swap_size = 0;
    int padding = RSA_PKCS1_PADDING;
    char swap_buffer[1024] = "";
    unsigned char* rsa_out;

    if (m_crypto_initialized != 0)//If init failed can not continue
        goto exit;
    *data_size = RSA_size(rsa);
    data = (uint8_t *)malloc(*data_size);
    TRACE_ENCLAVE("Start!RSA_public_encrypt Successful!.Time is %d",print_time2());
    ret = RSA_private_decrypt(encrypted_data_size, encrypted_data, data, rsa, padding);
    if (ret <= 0){
        TRACE_ENCLAVE("RSA Step Failed.RSA_public_encrypt failed!.");
        goto exit;
    }
    TRACE_ENCLAVE("RSA Step Successful Time is %d.RSA_private_decrypt Successful!.%s",print_time2(),data);
    ret = 0;
exit:
    //TODO Free something
    return ret;
}

/**
 * @brief Use my RSA private key to sign data
 * @param data the data for signning
 * @param data_size
 * @param rsa_sig_data signed data
 * @param rsa_sig_data_size
 * @return failure 1 success 0
 */
int Crypto::rsa_sign(
    const uint8_t *data,
    size_t data_size,
    uint8_t *rsa_sig_data,
    size_t *rsa_sig_data_size)
{
    TRACE_ENCLAVE("RSA_sign Start! Time %d",print_time2());
    unsigned char md[32];
    int ret = 1;
    unsigned char rsa_sig[256] = "";
    unsigned int rsa_sig_size = 0;
    if (m_crypto_initialized != 0)//If init failed can not continue
        goto exit;
    if (SHA256((unsigned char*)data, data_size, md) == NULL) {
		TRACE_ENCLAVE("sha256 erro\n");
		return -1;
	}    
    ret = RSA_sign(NID_md5,md,32,rsa_sig,&rsa_sig_size,rsa);
    if(ret != 1)
    {
        TRACE_ENCLAVE("RSA_sign failed");
        goto exit;
    }
    TRACE_ENCLAVE("RSA_sign Successful! Time %d",print_time2());
    memcpy(rsa_sig_data,rsa_sig,rsa_sig_size);//256
    *rsa_sig_data_size = rsa_sig_size;
    ret = 0;
exit:
    //TODO Free something
    return ret;
}

/**
 * @brief verify signature created by rsa
 * @param data
 * @param data_size
 * @param rsa_sig_data
 * @param rsa_sig_data_size
 * @return int
 */
int Crypto::rsa_verify(
    uint8_t *pem_public_key,
    size_t pem_public_key_size,
    const uint8_t *data,
    size_t data_size,
    uint8_t *rsa_sig_data,
    size_t rsa_sig_data_size)
{
    TRACE_ENCLAVE("Rsa_Verify Start! Time %d",print_time2());
    unsigned char md[32];
    int ret = 1;
    char swap_buffer[1024] = "";
    unsigned char rsa_sig[256] = "";
    RSA *rsa_recover = RSA_new();;
    BIO *temp = NULL;

    if (m_crypto_initialized != 0)//If init failed can not continue
        goto exit;
    if (SHA256((unsigned char*)data, data_size, md) == NULL) {
		TRACE_ENCLAVE("sha256 erro\n");
		return -1;
	}

    temp = BIO_new(BIO_s_mem());
    memcpy(swap_buffer,pem_public_key,pem_public_key_size);

    BIO_printf(temp, swap_buffer);
    if(temp == NULL){
        TRACE_ENCLAVE("Failed to BIO_new_mem_buf!");
        goto exit;
    }
    rsa_recover = PEM_read_bio_RSA_PUBKEY(temp, NULL, NULL, NULL); // Read public from BIO memory
    if (rsa_recover == NULL){
        TRACE_ENCLAVE("RSA Read public key failed.");
        goto exit;
    }
    memcpy(rsa_sig,rsa_sig_data,256);
    ret = RSA_verify(NID_md5,md,32,rsa_sig,256,rsa_recover);
    if(ret != 1)
    {
        TRACE_ENCLAVE("RSA Vefisy failed");
        goto exit;
    }
    TRACE_ENCLAVE("RSA Vefisy Successful!,Time is %d",print_time2());
    ret = 0;
exit:
    //TODO Free something
    return ret;
}

/**
 * @brief use aes to encrypt messages
 * @param data
 * @param data_size
 * @param encrypted_data
 * @param encrypted_data_size
 * @return int
 */
int Crypto::aes_encrypt(
    const uint8_t *data,
    size_t data_size,
    uint8_t *encrypted_data,
    size_t *encrypted_data_size,
    const uint8_t *aes_key){
        
    int ret = 1;
    AES_KEY AesKeys;
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    memset(iv,0,16);
    BIGNUM *temp_bn;
    BIO *temp = NULL;
    unsigned char *swap_buffer;
    unsigned char *swap_buffer_test;
    // TRACE_ENCLAVE(" init data %s", data);
    if (m_crypto_initialized != 0)//If init failed can not continue
        goto exit;
    swap_buffer = (unsigned char *)malloc(data_size + 128);
    memset(swap_buffer,0,data_size + 128);
    swap_buffer_test = (unsigned char *)malloc(data_size + 128);
    temp_bn = BN_new();
    BN_rand(bn,  AES_BLOCK_SIZE*8, -1, 1); //genc 16 iv
    // memcpy(iv,BN_bn2hex(bn), AES_BLOCK_SIZE);//Random iv
    if(AES_set_encrypt_key(aes_key,  AES_BLOCK_SIZE * 8, &AesKeys) < 0)
    {
        TRACE_ENCLAVE("AES_set_encrypt_key failed");
        goto exit;
    }
    TRACE_ENCLAVE("AES Encrypt Start!Time is %d.AES encrypt Successful!%d.",print_time2(),data_size);
    AES_cbc_encrypt(data,swap_buffer,data_size,&AesKeys,iv,AES_ENCRYPT);
    TRACE_ENCLAVE("AES Encrypt Finish Successful Time is %d.AES encrypt Successful!.",print_time2());
    // encrypted_data = (uint8_t *)malloc(strlen((const char*)swap_buffer) + AES_BLOCK_SIZE);
    // memcpy(encrypted_data,iv,AES_BLOCK_SIZE);
    // memcpy(encrypted_data + AES_BLOCK_SIZE,swap_buffer,strlen((const char*)swap_buffer));
    memcpy(encrypted_data,swap_buffer,data_size + 128);//FIXME AES Encrypt length
    *encrypted_data_size = data_size + 128;
    // *encrypted_data_size = sizeof(swap_buffer); 
    TRACE_ENCLAVE("AES Encrypt Finish Successful Time is %d.AES%d encrypt Successful!.And aes key is %s",*encrypted_data_size,data_size,aes_key);
    ret = 0;
exit:
    //TODO Free something
    return ret;
}

/**
 * @brief Decrypt encrypted messages by aes
 * @param data
 * @param data_size
 * @param deencrypted_data
 * @param decrypted_data_size
 * @param aes_key
 * @return int 0 success 1 failure
 */
int Crypto::aes_decrypt(
    const uint8_t *data,
    size_t data_size,
    uint8_t *deencrypted_data,
    size_t *decrypted_data_size,
    const uint8_t *aes_key)
{
    int ret = 1;
    AES_KEY AesKeys;
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    memset(iv,0,16);
    unsigned char *swap_buffer;
    // for(size_t i = 0; i <(data_size);i++)
    //     TRACE_ENCLAVE(" encrypted_data_size %x", data[i]);
    // for(size_t i = 0; i <(AES_BLOCK_SIZE * 8);i++)
    //     TRACE_ENCLAVE(" aes kye %d", aes_key[i]);
    TRACE_ENCLAVE("AES decrypt Start!.%d And aes key is %s",data_size,aes_key);
    if (m_crypto_initialized != 0)//If init failed can not continue
        goto exit;
    swap_buffer = (unsigned char *)malloc(data_size + 128);
    memset(swap_buffer,0,data_size + 128);
    if(AES_set_decrypt_key(aes_key,  AES_BLOCK_SIZE * 8, &AesKeys) < 0)
    {
        TRACE_ENCLAVE("AES_set_encrypt_key failed");
        goto exit;
    }
    
    // memcpy(iv,data,AES_BLOCK_SIZE);//Copy iv
    // AES_cbc_encrypt(data + AES_BLOCK_SIZE,swap_buffer,data_size - AES_BLOCK_SIZE,&AesKey,iv,AES_DECRYPT);
    AES_cbc_encrypt(data,swap_buffer,data_size,&AesKeys,iv,AES_DECRYPT);
    if(strlen((const char*)swap_buffer) > data_size + 128){
        TRACE_ENCLAVE("AES Encrypt failed.Your buffer is more small %d",strlen((const char*)swap_buffer) );
        goto exit;
    }
    memcpy(deencrypted_data, swap_buffer, strlen((const char*)swap_buffer));
    *decrypted_data_size = strlen((const char *)swap_buffer);
    TRACE_ENCLAVE("AES_set_encrypt_key %s aaa %d  %s",swap_buffer,*decrypted_data_size,deencrypted_data);

    ret = 0;
exit:
    //TODO Free something
    return ret;
}

/**
 * @brief use ecdsa private key to sign messages
 * @param data  data
 * @param data_size
 * @param sign_data signing data
 * @param sign_data_size
 * @return true
 * @return false
 */
//NOTE This ecdsa on openssl implement
int Crypto::ecdsa_signed_openssl(
    const uint8_t *data,
    size_t data_size,
    uint8_t *sign_data,
    size_t *sign_data_size
    ){
        int ret = 1;
        unsigned char sig[512];
        unsigned int sig_len = 0;
        unsigned char md[32];
        TRACE_ENCLAVE("ECDSA Step 1");
        if (SHA256((const unsigned char*)data, data_size, md) == NULL) {
            TRACE_ENCLAVE("sha256 erro\n");
            goto exit;
        }
        TRACE_ENCLAVE("ECDSA Step 2");
        
        ret = ECDSA_sign(0,md,32,sig,&sig_len,eckey);
        if(ret == -1)
        {
            TRACE_ENCLAVE("ECDSA Step failed.ECDSA_do_sign Failed");
            goto exit;
        }
        TRACE_ENCLAVE("ECDSA Step 2");
        memcpy(sign_data, sig, sig_len);
        TRACE_ENCLAVE("ECDSA Step 2");
        *sign_data_size = sig_len;
        ret = 0;
        TRACE_ENCLAVE("ECDSA Step Successful!");
    exit:
        return ret;
}


/**
 * @brief verify signature created by ecdsa sk
 * @param data
 * @param data_size
 * @param sig
 * @param sig_size
 * @param ecdsa_public_key
 * @param ecdsa_public_key_size
 * @return true
 */
// openssl ecdsa verify implement.
int Crypto::ecdsa_verify_openssl(
    const uint8_t *data,
    size_t data_size,
    const uint8_t *sig,
    size_t sig_size,
    const uint8_t *ecdsa_public_key,
    size_t ecdsa_public_key_size){
        int ret = 1;
        unsigned char md[32];

        BIO *bufio; // use a bufio to convert 
        EC_KEY *recover_eckey = NULL;
        bufio = BIO_new(BIO_s_mem());// Create a new BIO in 
        TRACE_ENCLAVE("Debug Test. uint8_t cover to char ! And time is %d",print_time2());
        BIO_printf(bufio, (char *)ecdsa_public_key); // Read public key into BIO memory
        if(bufio == NULL){
            TRACE_ENCLAVE("Failed to BIO_new_mem_buf!");
            goto exit;
        }
        recover_eckey = PEM_read_bio_EC_PUBKEY(bufio, NULL, NULL, NULL); // Read public from BIO 
        if (SHA256((unsigned char*)data, data_size, md) == NULL) {
            TRACE_ENCLAVE("sha256 erro\n");
            goto exit;
        }        
        ret = ECDSA_verify(0,md,32,sig,sig_size,recover_eckey);
        if (ret == -1){
            TRACE_ENCLAVE("ECDSA Step failed.ECDSA_do_verify error.");
            goto exit;
        }
        else if (ret == 0){
            TRACE_ENCLAVE("ECDSA Step failed.ECDSA_do_verify incorrect signature.");
            goto exit;
        }
        else{
            TRACE_ENCLAVE("ECDSA Step Successful.ECDSA_do_verify Successful!.");
        }
        ret = 0;
    exit:
        return ret;
}
