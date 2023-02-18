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
#include "ed25519/Ed25519.h"

Crypto::Crypto()
{
    m_crypto_initialized = init_openssl();
}

Crypto::~Crypto()
{
    cleanup_openssl();
}

// INFO Print time for function runtime
int64_t print_time2()
{

    std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    return ms.count();
}

/**
 * @brief init crypto object including initialization of ecdsa、aes、rsa、hash
 * @return true
 * @return false
 */
int Crypto::init_openssl(void)
{
    // implement openssl
    int ret = 1;
    rsa = RSA_new();
    e = BN_new();
    BN_set_word(e, 17);
    gencb = NULL;
    pkey = EVP_PKEY_new();
    ret = RSA_generate_key_ex(rsa, 2048, e, gencb);
    ret = EVP_PKEY_set1_RSA(pkey, rsa);
    if (ret == 0)
    {
        TRACE_ENCLAVE("OpenSsl Generate RSA Key failed.");
        return ret;
    }
    out = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_RSA_PUBKEY(out, rsa); // take rsa pubkey
    if (ret == 0)
    { // PEM_write_bio_RSA_PUBKEY return 1 representation successful
        TRACE_ENCLAVE("ECDSA Step failed.PEM_write_bio_EC_PUBKEY Failed");
        ret = 1;
        return ret;
    }
    swap_pp_size = BIO_read(out, swap_pp, BIO_get_mem_data(out, nullptr)); // NID_secp192k1 ecdsa length is 150
    if (swap_pp_size == 0)                                                 // If the result is 0 or -1, the read fails
    {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        ret = 1;
        return ret;
    }
    memcpy(m_rsa_public_key, swap_pp, sizeof(m_rsa_public_key));
    memset(swap_pp, 0, sizeof(swap_pp));
    ret = BIO_reset(out); // reset out BIO
    if (ret != 1)
    {
        TRACE_ENCLAVE("ECDSA Step BIO reset failed.");
        ret = 1;
        return ret;
    }
    ret = PEM_write_bio_RSAPrivateKey(out, rsa, 0, 0, 0, 0, 0);
    if (ret == 0)
    { // PEM_write_bio_RSA_PUBKEY return 1 representation successful
        TRACE_ENCLAVE("ECDSA Step failed.PEM_write_bio_EC_PUBKEY Failed");
        ret = 1;
        return ret;
    }
    swap_pp_size = BIO_read(out, swap_pp, BIO_get_mem_data(out, nullptr)); // NID_secp192k1 ecdsa length is 150
    if (swap_pp_size == 0)                                                 // If the result is 0 or -1, the read fails
    {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        ret = 1;
        return ret;
    }
    memcpy(m_rsa_private_key, swap_pp, sizeof(m_rsa_private_key)); // distill the private key
    memset(swap_pp, 0, sizeof(swap_pp));
    ret = BIO_reset(out); // reset out BIO
    if (ret != 1)
    {
        TRACE_ENCLAVE("ECDSA Step BIO reset failed.");
        ret = 1;
        return ret;
    }
    TRACE_ENCLAVE("OpenSsl RSA step init Successful!");
    // AES Openssl implement
    // Genc a aes key
    bn = BN_new();
    BN_rand(bn, AES_BLOCK_SIZE * 8, -1, 1); // genc 128 bit random
    memcpy(m_aes_key, BN_bn2hex(bn), AES_BLOCK_SIZE * 8);
    BN_free(bn); // Free bignum
    TRACE_ENCLAVE("AES Key is %s", m_aes_key);
    if (AES_set_encrypt_key(m_aes_key, AES_BLOCK_SIZE * 8, &AesKey) < 0)
    {
        TRACE_ENCLAVE("AES_set_encrypt_key failed");
        ret = 1;
        return ret;
    }
    TRACE_ENCLAVE("OpenSsl AES step init Successful!");
    // INIT Ecdsa
    eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1); // Choose ecdsa curve
    if (eckey == NULL)
    {
        TRACE_ENCLAVE("ECDSA Step failed. EC_KEY_new_by_curve_name Failed");
        ret = 1;
        return ret;
    }
    if (!EC_KEY_generate_key(eckey))
    { // Genc the ec key
        TRACE_ENCLAVE("ECDSA Step failed.EC_KEY_generate_key Failed");
        ret = 1;
        return ret;
    }
    // extract ECDSA public key
    //  out = BIO_new(BIO_s_mem());
    ret = PEM_write_bio_EC_PUBKEY(out, eckey);
    if (ret == 0)
    { // PEM_write_bio_EC_PUBKEY return 1 representation successful
        TRACE_ENCLAVE("ECDSA Step failed.PEM_write_bio_EC_PUBKEY Failed");
        ret = 1;
        return ret;
    }
    swap_pp_size = BIO_read(out, swap_pp, BIO_get_mem_data(out, nullptr)); // NID_secp192k1 ecdsa length is 150
    // TRACE_ENCLAVE("ECDSA Step failed.BIO new %d  %s",ret,swap_pp);
    if (swap_pp_size == 0) // If the result is 0 or -1, the read fails
    {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        ret = 1;
        return ret;
    }
    memcpy(m_ecdsa_public_key, swap_pp, sizeof(m_ecdsa_public_key)); // distill the private key
    memset(swap_pp, 0, sizeof(swap_pp));
    ret = BIO_reset(out); // reset out BIO
    if (ret != 1)
    {
        TRACE_ENCLAVE("ECDSA Step BIO reset failed.");
        ret = 1;
        return ret;
    }
    ret = PEM_write_bio_ECPrivateKey(out, eckey, NULL, NULL, 0, NULL, NULL); // ecdsa private key
    swap_pp_size = BIO_read(out, swap_pp, BIO_get_mem_data(out, nullptr));   // NID_secp192k1 ecdsa length is 150
    if (swap_pp_size == 0)                                                   // If the result is 0 or -1, the read fails
    {
        TRACE_ENCLAVE("ECDSA Step failed.BIO_get_mem_data Failed");
        ret = 1;
        return ret;
    }
    memcpy(m_ecdsa_private_key, swap_pp, sizeof(m_ecdsa_private_key)); // distill the private key
    memset(swap_pp, 0, sizeof(swap_pp));
    ret = BIO_reset(out); // reset out BIO

    // load the ed25519 public key
    uint8_t **tmp_buffer;
    oe_result_t result;
    *tmp_buffer = (uint8_t *)oe_host_malloc(32);
    // Test for aliyun
    // result = load_ed25519(&ret, tmp_buffer);
    // if (result != OE_OK)
    // {
    //     TRACE_ENCLAVE("Ocall load_ed25519 is failed.");
    //     ret = 1;
    //     return ret;
    // }
    // memcpy(ed25519_public_key, *tmp_buffer, 32);
    TRACE_ENCLAVE("OpenSsl ECDSA step init Successful!");
    // BUG Here is a double pointer no free. If call oe_free this pointer, program will crash with :OE_ENCLAVE_ABORTING
    //  oe_free(*tmp_buffer);
    //  *tmp_buffer = NULL;
    //  oe_free(tmp_buffer);
    ret = 0;
    TRACE_ENCLAVE("Openssl initialized.the ret is %d", ret);

    return ret;
}

void Crypto::cleanup_openssl(void)
{
    // TODO clean function
    TRACE_ENCLAVE("openssl cleaned up.");
}

// Compute the sha256 hash of given data.
int Crypto::Sha256(const uint8_t *data, size_t data_size, uint8_t sha256[32])
{
    int ret = 0;
    if (SHA256((unsigned char *)data, data_size, sha256) == NULL)
    {
        TRACE_ENCLAVE("sha256 erro\n");
        ret = 1;
        return ret;
    }

    return ret;
}

/**
 * @brief  Ed25519 Signature interface
 *
 * @param msg
 * @param msg_size
 * @param signature
 * @return int 0 Success 1 Fail
 */
int Crypto::Ed25519(const uint8_t *msg, size_t msg_size, uint8_t signature[64])
{
    // uint8_t publicKey[32] = {0xCA, 0x45, 0xC1, 0x30, 0xD, 0x22, 0x2B, 0xCC, 0xD7, 0x81, 0x6A, 0x5C, 0x9C, 0x5E, 0x7, 0x8F, 0x59, 0xA7, 0x48, 0x44, 0x78, 0xBE, 0xAE, 0xC9, 0xB1, 0xCE, 0x2A, 0xA1, 0xFD, 0x90, 0x78, 0xF0};
    // Ed25519::sign(signature, privateKey, publicKey, msg, 17);
    if (!Ed25519::verify(signature, ed25519_public_key, msg, msg_size))
    {
        TRACE_ENCLAVE("The signature:");
        for (uint8_t i = 0; i < 64; i++)
        {
            printf("%x ", signature[i]);
        }
        TRACE_ENCLAVE("The msg: size is %d", msg_size);
        for (uint8_t i = 0; i < msg_size; i++)
        {
            printf("%x ", msg[i]);
        }
        TRACE_ENCLAVE("Ed25519 Signature Error! Please check msg and signature for consistency.");
        return 1;
    }
    TRACE_ENCLAVE("Ed25519 Signature Successful!");
    return 0;
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
    RSA *rsa_recover = RSA_new();
    BIO *temp = NULL;
    int encrypt_len = 0;
    long swap_size = 0;
    int padding = RSA_PKCS1_PADDING;
    char *swap_buffer;
    unsigned char *rsa_out;

    if (m_crypto_initialized != 0) // If init failed can not continue
    {
        TRACE_ENCLAVE("m_crypto_initialized failed!");
        ret = 1;
        return ret;
    }
    temp = BIO_new(BIO_s_mem());
    swap_buffer = (char *)malloc(pem_public_key_size + 1);
    memset(swap_buffer, 0, pem_public_key_size + 1);
    memcpy(swap_buffer, pem_public_key, pem_public_key_size);
    TRACE_ENCLAVE("PK %d IS %s", pem_public_key_size, m_rsa_public_key);
    BIO_printf(temp, swap_buffer);
    if (temp == NULL)
    {
        TRACE_ENCLAVE("Failed to BIO_new_mem_buf!");
        ret = 1;
        return ret;
    }
    free(swap_buffer);
    swap_buffer = NULL;
    rsa_recover = PEM_read_bio_RSA_PUBKEY(temp, NULL, NULL, NULL); // Read public from BIO memory
    if (rsa_recover == NULL)
    {
        TRACE_ENCLAVE("RSA Read public key failed.");
        ret = 1;
        return ret;
    }
    // TRACE_ENCLAVE("Start!RSA_public_encrypt Start!.Time is %d", print_time2());
    encrypt_len = RSA_size(rsa_recover);
    rsa_out = (unsigned char *)malloc(encrypt_len + 1);
    ret = RSA_public_encrypt((int)data_size, data, rsa_out, rsa_recover, padding);
    if (ret <= 0)
    {
        TRACE_ENCLAVE("RSA Step Failed.RSA_public_encrypt failed!.");
        ret = 1;
        return ret;
    }
    // TRACE_ENCLAVE("Finish!RSA_public_encrypt Successful!.Time is %d", print_time2());

    memcpy(encrypted_data, rsa_out, encrypt_len);
    *encrypted_data_size = encrypt_len;
    // TRACE_ENCLAVE("Finish!RSA_public_encrypt Successful!.Time is %d", print_time2());
    ret = 0;

    RSA_free(rsa_recover);
    rsa_recover = NULL;
    BIO_free(temp);
    temp = NULL;
    oe_free(rsa_out);
    rsa_out = NULL;
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
    int padding = RSA_PKCS1_PADDING;
    if (m_crypto_initialized != 0)
    {
        ret = 1;
        return ret;
    }
    *data_size = RSA_size(rsa);
    ret = RSA_private_decrypt(encrypted_data_size, encrypted_data, data, rsa, padding);
    if (ret <= 0)
    {
        TRACE_ENCLAVE("RSA Step Failed.RSA_public_encrypt failed!.");
        ret = 1;
        return ret;
    }
    ret = 0;
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
    unsigned char md[32];
    int ret = 1;
    unsigned char rsa_sig[256] = "";
    unsigned int rsa_sig_size = 0;

    if (m_crypto_initialized != 0) // If init failed can not continue
    {
        ret = 1;
        return ret;
    }

    if (SHA256((unsigned char *)data, data_size, md) == NULL)
    {
        TRACE_ENCLAVE("sha256 erro\n");
        ret = 1;
        return ret;
    }

    ret = RSA_sign(NID_md5, md, 32, rsa_sig, &rsa_sig_size, rsa);
    if (ret != 1)
    {
        TRACE_ENCLAVE("RSA_sign failed");
        ret = 1;
        return ret;
    }

    memcpy(rsa_sig_data, rsa_sig, rsa_sig_size);
    *rsa_sig_data_size = rsa_sig_size;
    ret = 0;
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
    unsigned char md[32];
    int ret = 1;
    char swap_buffer[1024] = "";
    unsigned char rsa_sig[256] = "";
    RSA *rsa_recover = RSA_new();
    BIO *temp = NULL;

    if (m_crypto_initialized != 0) // If init failed can not continue
    {
        ret = 1;
        return ret;
    }
    if (SHA256((unsigned char *)data, data_size, md) == NULL)
    {
        TRACE_ENCLAVE("sha256 erro\n");
        return -1;
    }

    temp = BIO_new(BIO_s_mem());
    memcpy(swap_buffer, pem_public_key, pem_public_key_size);

    BIO_printf(temp, swap_buffer);
    if (temp == NULL)
    {
        TRACE_ENCLAVE("Failed to BIO_new_mem_buf!");
        ret = 1;
        return ret;
    }
    rsa_recover = PEM_read_bio_RSA_PUBKEY(temp, NULL, NULL, NULL); // Read public from BIO memory
    if (rsa_recover == NULL)
    {
        TRACE_ENCLAVE("RSA Read public key failed.");
        ret = 1;
        return ret;
    }
    memcpy(rsa_sig, rsa_sig_data, 256);
    ret = RSA_verify(NID_md5, md, 32, rsa_sig, 256, rsa_recover);
    if (ret != 1)
    {
        TRACE_ENCLAVE("RSA Vefisy failed");
        ret = 1;
        return ret;
    }
    // TRACE_ENCLAVE("RSA Vefisy Successful!,Time is %d", print_time2());
    ret = 0;

    RSA_free(rsa_recover);
    rsa_recover = NULL;
    BIO_free(temp);
    temp = NULL;
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
    const uint8_t *aes_key)
{
    int ret = 1;
    AES_KEY AesKeys;
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);
    BIO *temp = NULL;
    unsigned char *swap_buffer = NULL;

    if (m_crypto_initialized != 0)
    {
        ret = 1;
        return ret;
    }

    swap_buffer = (unsigned char *)malloc(data_size + 128);
    if (swap_buffer == nullptr)
    {
        TRACE_ENCLAVE("buffer malloc failed");
        ret = 1;
        return ret;
    }
    memset(swap_buffer, 0, data_size + 128);
    if (AES_set_encrypt_key(aes_key, AES_BLOCK_SIZE * 8, &AesKeys) < 0)
    {
        TRACE_ENCLAVE("AES_set_encrypt_key failed");
        ret = 1;
        return ret;
    }
    AES_cbc_encrypt(data, swap_buffer, data_size, &AesKeys, iv, AES_ENCRYPT);
    memcpy(encrypted_data, swap_buffer, data_size + 128);
    *encrypted_data_size = data_size + 128;
    ret = 0;
    oe_free(swap_buffer);
    swap_buffer = NULL;
    BIO_free(temp);
    temp = NULL;
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
    unsigned char iv[AES_BLOCK_SIZE];
    memset(iv, 0, AES_BLOCK_SIZE);
    unsigned char *swap_buffer;

    if (m_crypto_initialized != 0) // If init failed can not continue
    {
        ret = 1;
        return ret;
    }

    swap_buffer = (unsigned char *)malloc(data_size + 128);
    if (swap_buffer == nullptr)
    {
        TRACE_ENCLAVE("malloc failed");
        ret = 1;
        return ret;
    }
    memset(swap_buffer, 0, data_size + 128);
    if (AES_set_decrypt_key(aes_key, AES_BLOCK_SIZE * 8, &AesKeys) < 0)
    {
        TRACE_ENCLAVE("AES_set_encrypt_key failed");
        ret = 1;
        return ret;
    }

    AES_cbc_encrypt(data, swap_buffer, data_size, &AesKeys, iv, AES_DECRYPT);
    if (strlen((const char *)swap_buffer) > data_size + 128)
    {
        TRACE_ENCLAVE("AES Encrypt failed.Your buffer is more small %d", strlen((const char *)swap_buffer));
        ret = 1;
        return ret;
    }
    memcpy(deencrypted_data, swap_buffer, data_size + 128);
    *decrypted_data_size = data_size + 128;

    ret = 0;
    oe_free(swap_buffer);
    swap_buffer = NULL;
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
// NOTE This ecdsa on openssl implement
int Crypto::ecdsa_signed_openssl(
    const uint8_t *data,
    size_t data_size,
    uint8_t *sign_data,
    size_t *sign_data_size)
{
    int ret = 1;
    unsigned char sig[512];
    unsigned int sig_len = 0;
    unsigned char md[32];
    if (SHA256((const unsigned char *)data, data_size, md) == NULL)
    {
        TRACE_ENCLAVE("sha256 erro\n");
        ret = 1;
        return ret;
    }
    ret = ECDSA_sign(0, md, 32, sig, &sig_len, eckey);
    if (ret == -1)
    {
        TRACE_ENCLAVE("ECDSA Step failed.ECDSA_do_sign Failed");
        ret = 1;
        return ret;
    }
    memcpy(sign_data, sig, sig_len);
    *sign_data_size = sig_len;
    ret = 0;
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
    size_t ecdsa_public_key_size)
{
    int ret = 1;
    unsigned char md[32];
    char swap_buffer[2048] = "";
    BIO *bufio; // use a bufio to convert
    EC_KEY *recover_eckey = NULL;
    bufio = BIO_new(BIO_s_mem()); // Create a new BIO in
    TRACE_ENCLAVE("Debug Test.%d uint8_t cover to char ! %sAnd time is %d", ecdsa_public_key_size, ecdsa_public_key, print_time2());
    memcpy(swap_buffer, ecdsa_public_key, ecdsa_public_key_size);
    BIO_printf(bufio, swap_buffer); // Read public key into BIO memory
    if (bufio == NULL)
    {
        TRACE_ENCLAVE("Failed to BIO_new_mem_buf!");
        ret = 1;
        return ret;
    }

    recover_eckey = PEM_read_bio_EC_PUBKEY(bufio, NULL, NULL, NULL); // Read public from BIO
    if (recover_eckey == NULL)
    {
        TRACE_ENCLAVE("Failed to read pubkey!");
        ret = 1;
        return ret;
    }
    if (SHA256((unsigned char *)data, data_size, md) == NULL)
    {
        TRACE_ENCLAVE("sha256 erro\n");
        ret = 1;
        return ret;
    }
    TRACE_ENCLAVE("Debug Test. uint8_t cover to char ! And time is %d", print_time2());

    ret = ECDSA_verify(0, md, 32, sig, sig_size, recover_eckey);
    if (ret == -1)
    {
        TRACE_ENCLAVE("ECDSA Step failed.ECDSA_do_verify error.");
        ret = 1;
        return ret;
    }
    else if (ret == 0)
    {
        TRACE_ENCLAVE("ECDSA Step failed.ECDSA_do_verify incorrect signature.");
        ret = 1;
        return ret;
    }
    else
    {
        TRACE_ENCLAVE("ECDSA Step Successful.ECDSA_do_verify Successful!.");
    }
    ret = 0;
exit:
    return ret;
}
