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
#ifndef OE_SAMPLES_ATTESTATION_ENC_CRYPTO_H
#define OE_SAMPLES_ATTESTATION_ENC_CRYPTO_H

#include <openenclave/enclave.h>


#include "log.h"
#include <openenclave/enclave.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/aes.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>



#define OE_RSA_PRIVATE_KEY_SIZE 2048
#define PUBLIC_KEY_SIZE 512
#define PRINT_CRYPTO_MESSAGE 1
#define Aes_Key_Size 128

class Crypto
{
private:
  // Init Crypto env

  // uint8_t m_rsa_public_key[PUBLIC_KEY_SIZE];
  // uint8_t m_rsa_private_key[OE_RSA_PRIVATE_KEY_SIZE];
  uint8_t m_ecdsa_public_key[256];
  uint8_t m_ecdsa_private_key[PUBLIC_KEY_SIZE];
  int m_crypto_initialized;
  uint8_t m_other_ecdsa_pubkey[256];
  size_t uuid;
  // Public key of another enclave.
  uint8_t m_other_enclave_pubkey[PUBLIC_KEY_SIZE];

  //Openssl implement

  //ECDSA implement
  EC_KEY *eckey = NULL;
  BIO *out = NULL;
  // const unsigned char dgst[32] = "1234567890123456789110123456789";
  unsigned char sig[1024];
  unsigned int sig_len = 0;
  // long swap_pp_size = 0;
  BIO *recover_BIO = NULL;
  EC_KEY *recover_eckey = NULL;

  uint8_t m_rsa_public_key[PUBLIC_KEY_SIZE];
  uint8_t m_rsa_private_key[OE_RSA_PRIVATE_KEY_SIZE];
  uint8_t other_rsa_public_key[PUBLIC_KEY_SIZE];
  uint8_t ecdsa_public_key_openssl[256] = "";//ecdsa size
  uint8_t ecdsa_private_key_openssl[256] = "";//ecdsa size
  uint8_t m_aes_key[128];
  uint8_t m_aes_iv[16] = {0}; /*initial iv value for aes*/

  RSA *rsa;
  BIGNUM *e;
  BN_GENCB* gencb;
  EVP_PKEY* pkey;
  int out_len;
  int in_len;
  char swap_pp[2048];
  long swap_pp_size = 0;
  AES_KEY AesKey;
  // char *Aes_Key;
  unsigned char Aes_Key[128];
  unsigned char ivec[16];	
  BIGNUM *bn;
  unsigned char in[10] = "11111111";
  unsigned char aes_aout[10];
  unsigned char iv[AES_BLOCK_SIZE] = {0};
  unsigned char* rsa_out;
  unsigned char* plainText;
  int padding = RSA_PKCS1_PADDING;


public:
  Crypto();
  ~Crypto();

  // Get this enclave's own public key
  uint8_t *get_rsa_public_key()
  {
    return m_rsa_public_key;
  }

  // retrieve self aes  key
  void get_aes_key(uint8_t aes_key[Aes_Key_Size])
  {
    memcpy(aes_key, m_aes_key, sizeof(m_aes_key));
  }

  // get ecdsa public key
  uint8_t *get_ecdsa_pubkey_key()
  {
    return m_ecdsa_public_key;
  }

  // get ecdsa public key
  uint8_t *get_ecdsa_prikey_key()
  {
    return m_ecdsa_private_key;
  }

  void copy_other_rsa_key(uint8_t *rsa_public_key, size_t rsa_public_key_size)
  {
    memcpy(other_rsa_public_key, rsa_public_key, rsa_public_key_size);
  }
    void retrieve_othet_rsa_public_key(uint8_t rsa_public_key[512])
  {
    memcpy(rsa_public_key, other_rsa_public_key, sizeof(other_rsa_public_key));
  }


  void set_my_uuid(size_t id)
  {
    uuid = id;
  }

  size_t get_my_uuid()
  {
    return uuid;
  }
  // copy this enclave's own public key
  void copy_rsa_public_key(uint8_t rsa_public_key[512])
  {
    memcpy(rsa_public_key, m_rsa_public_key, sizeof(m_rsa_public_key));
  }

  // copy aes key
  void copy_aes_key(uint8_t aes_key[128])
  {
    memcpy(aes_key, m_aes_key, sizeof(m_aes_key));
  }

  // copy ecdsa public key
  void copy_ecdsa_pubkey_key(uint8_t ecdsa_public_key[256])
  {
    memcpy(ecdsa_public_key, m_ecdsa_public_key, sizeof(m_ecdsa_public_key));
  }
  // copy ecdsa public key
  void copy_ecdsa_pri_key(uint8_t ecdsa_prikey_key[256])
  {
    memcpy(ecdsa_prikey_key, m_ecdsa_private_key, sizeof(m_ecdsa_private_key));
  }


  // Compute the sha256 hash of given data.
  int Sha256(const uint8_t *data, size_t data_size, uint8_t sha256[32]);

  // rsa encrypt funtion
  int rsa_encrypt(
      uint8_t *pem_public_key,
      size_t pem_public_key_size,
      const uint8_t *data,
      size_t size,
      uint8_t *encrypted_data,
      size_t *encrypted_data_size);

  // rsa decrypt funtion
  int rsa_decrypt(
      const uint8_t *encrypted_data,
      size_t encrypted_data_size,
      uint8_t *data,
      size_t *data_size);

  // RSA sign function
  int rsa_sign(
      const uint8_t *data,
      size_t data_size,
      uint8_t *rsa_sig_data,
      size_t *rsa_sig_data_size);

  int rsa_verify(
      uint8_t *pem_public_key,
      size_t pem_public_key_size,
      const uint8_t *data,
      size_t data_size,
      uint8_t *rsa_sig_data,
      size_t rsa_sig_data_size);

  // AES encrypt messages
  int aes_encrypt(
      const uint8_t *data,
      size_t data_size,
      uint8_t *encrypted_data,
      size_t *encrypted_data_size,
      const uint8_t *aes_key);

  // Ed25519 Signature interface
  int Ed25519(
      const uint8_t *msg,
      size_t msg_size,
      uint8_t signature[64]);

  // AES decrypt messages
  int aes_decrypt(
      const uint8_t *data,
      size_t data_size,
      uint8_t *deencrypted_data,
      size_t *decrypted_data_size,
      const uint8_t *aes_key);

  // ecdsa_verify_sign Function
  int ecdsa_verify_openssl(
      const uint8_t *data,
      size_t data_size,
      const uint8_t *sig,
      size_t sig_size,
      const uint8_t *ecdsa_public_key,
      size_t ecdsa_public_key_size);



  // ecdsa_sign Function
  int ecdsa_signed_openssl(
      const uint8_t *data,
      size_t data_size,
      uint8_t *sign_data,
      size_t *sign_data_size);



private:

  // init_openssl initializes the crypto module.
  // int init_openssl(void);
  int init_openssl(void);
  void cleanup_openssl(void);
};

#endif
