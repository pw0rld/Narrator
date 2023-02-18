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

#pragma once
#include <openenclave/enclave.h>
#include <openenclave/seal.h>
#include <openenclave/corelibc/stdlib.h>
#include "common/attestation_t.h"
#include <string>
#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>
#include "attestation.h"
#include "crypto.h"

#define PRINT_DISPATCH_MESSAGES 1

using namespace std;

typedef struct _enclave_config_data
{
  uint8_t *enclave_secret_data;
  const char *other_enclave_public_key_pem;
  size_t other_enclave_public_key_pem_size;
} enclave_config_data_t;

typedef struct _peer_info
{
  size_t uuid;
  uint8_t rsa_public_key[512] = {0};
  size_t rsa_key_size;
  uint8_t ecdsa_public_key[256] = {0};
  size_t ecdsa_key_size;
  uint8_t aes_key[128] = {0};
  size_t aes_key_size;
  bool state = false;
  int quorum = 0;
  int nonce = 0;
  uint8_t ITHash[32] = {0};
  bool operator==(const size_t &e)
  {
    return (this->uuid == e); // redefined ==
  }
} peer_info_t;

typedef struct _state_info
{
  uint8_t hash[32];
  size_t index;
} state_info;

typedef struct ae_queue
{
  int index = 0;
  size_t uuid = 0;
  uint8_t encrypt_data[2048] = {0};
  uint8_t encrypt_data_size = 0;
} Ae_queues;

typedef struct ae_queue_decrypt
{
  size_t uuid = 0;
  uint8_t ITHash[32] = {0};
} Ae_queues_decrypt;

typedef struct _client_info
{
  uint8_t mrenclave[32];
  uint8_t aes_key[128];
  state_info *state_ptr;
} client_info;

// INFO Here is ROTE implementation
typedef struct Local_AE_counter_table
{
  size_t ASE_uuid;
  uint8_t m_aes_key[128];
  uint8_t ITHash[32];
  int nonce = 0;
  bool operator==(const size_t &e)
  {
    return (this->ASE_uuid == e); // redefined ==
  }
};

typedef struct _Re_persistent_state
{
  uint8_t m_aes_key[128];
  uint8_t m_ecdsa_public_key[256];
  uint8_t m_ecdsa_private_key[256];
  int Ae_requests = 0;
  int quorum = 0;
  int second = 0;
  uint8_t ITHash[32];
  vector<Local_AE_counter_table> local_aes;
} Re_persistent_state;

class ecall_dispatcher
{
private:
  int m_initialized;
  Crypto *m_crypto;
  Attestation *m_attestation;
  string m_name;
  std::vector<Ae_queues_decrypt> batch_queue_decrypt;
  // vector<peer_info_t> peer_info_vec;
  vector<peer_info_t> peer_info_vec2;
  vector<client_info> client_info_vec;
  int nonce = 0;
  // vector<Re_runtime_table> Re_runtime_tables;
  Re_persistent_state Re_persistent_state_table;
  enclave_config_data_t *m_enclave_config;
  unsigned char m_enclave_signer_id[32];

public:
  ecall_dispatcher(const char *name, enclave_config_data_t *enclave_config);
  ~ecall_dispatcher();

  int LedgerRead_key(uint8_t **publickey_id, size_t *publickey_id_size/*, uint8_t **sgx_uid, size_t *sgx_uid_size*/);
  int LedgerRead_other_key(uint8_t **publickey_id, size_t *publickey_id_size, uint8_t **sgx_uid, size_t *sgx_uid_size, size_t uuid);

  int verify_ed25519(uint8_t *signture, size_t signture_size, uint8_t *source_text, size_t source_text_size);

  int get_enclave_format_settings(
      const oe_uuid_t *format_id,
      uint8_t **format_settings,
      size_t *format_settings_size);

  int get_evidence_with_public_key(
      const oe_uuid_t *format_id,
      uint8_t *format_settings,
      size_t format_settings_size,
      uint8_t **pem_key,
      size_t *pem_key_size,
      uint8_t **evidence_buffer,
      size_t *evidence_buffer_size);

  int verify_evidence(
      const oe_uuid_t *format_id,
      uint8_t *pem_key,
      size_t pem_key_size,
      uint8_t *evidence,
      size_t evidence_size,
      size_t uuid);

  int rsa_encrypt_and_sig_aes(
      uint8_t **rsa_public_key,
      size_t *rsa_public_key_size,
      uint8_t **encrypt_aes_data,
      size_t *encrypt_aes_data_size,
      uint8_t **sig_aes_data,
      size_t *sig_aes_data_size,
      size_t uuid);

  int aes_encrypt_ecdsa(
      uint8_t **encrypt_aes_data,
      size_t *encrypt_aes_data_size,
      size_t uuid);

  int aes_decrypt_client_messages(
      uint8_t *encrypt_aes_data,
      size_t encrypt_aes_data_size,
      uint8_t *mrenclave,
      size_t mrenclave_size,
      uint8_t **reply_data,
      size_t *reply_data_size,
      size_t client_id,
      size_t *reply_type);

  int Init_system_state(
      vector<client_info>::iterator it);

  string get_latest_client_state(
      vector<client_info>::iterator it);

  int rsa_decrypt_verify_sig_and_set_aes(
      uint8_t *rsa_public_key,
      size_t rsa_public_key_size,
      uint8_t *encrypt_aes_data,
      size_t encrypt_aes_data_size,
      uint8_t *sig_aes_data,
      size_t sig_aes_data_size);

  int rsa_decrypt_client_aes(
      uint8_t *encrypt_aes_data,
      size_t encrypt_aes_data_size,
      uint8_t *mrenclave,
      size_t mrenclave_size,
      size_t uuid);

  int aes_decrypt_ecdsa_reply(
      uint8_t *encrypt_aes_data,
      size_t encrypt_aes_data_size,
      size_t uuid);

  int create_kpi_certificate_ecall(
      uint8_t **pki_certificate,
      size_t *pki_certificate_size,
      size_t uuid);

  int process_kpi_certificate_ecall(
      uint8_t *pki_certificate,
      size_t pki_certificate_size,
      size_t uuid);

  void set_uuid_ecall(size_t uuid);

  int ecdsa_sign_message(
      int policy,
      uint8_t *data,
      size_t data_size,
      uint8_t **sig,
      size_t *sig_size);

  int ecdsa_verify_sign_message(
      uint8_t *data,
      size_t data_size,
      uint8_t *sig_data,
      size_t sig_data_size,
      uint8_t *ecdsa_key,
      size_t ecdsa_key_size);

  int seal_state_data(
      int seal_policy,
      sealed_data_t **sealed_data,
      size_t *sealed_data_size);

  // int unseal_state_data(
  //     const sealed_data_t *sealed_data,
  //     size_t sealed_data_size,
  //     unsigned char **data,
  //     size_t *data_size);

  bool compare_key(
      uint8_t *key1,
      uint8_t *key2,
      size_t key_size);

  // INFO ROTE

  int updateLocalASECounterTable(size_t AE_uuid, uint8_t *ITHash, size_t ITHash_size);

  int ecdsa_signed(size_t AE_uuid,
                   int policy,
                   unsigned char **signed_data,
                   size_t *signed_data_size,
                   unsigned char **encrypt_data,
                   size_t *encrypt_data_size);

  int verify(
      size_t AE_uuid,
      int policy,
      unsigned char *sig_data,
      size_t sig_data_size,
      unsigned char *encrypt_data,
      size_t encrypt_data_size);

  int acceptNewState(int sealPolicy);

  int signed_with_verify(size_t AE_uuid,
                         int policy,
                         unsigned char *sig_data,
                         size_t sig_data_size,
                         unsigned char *encrypt_data,
                         size_t encrypt_data_size,
                         int signed_policy,
                         unsigned char **signed_data,
                         size_t *signed_data_size,
                         unsigned char **encrypt_data_out,
                         size_t *encrypt_data_out_size);

  void print_peers();

private:
  int initialize(const char *name);
};
