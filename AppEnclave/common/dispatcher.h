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
#include <string>
#include <iostream>
#include <fstream>
#include <map>
#include <sstream>
#include <vector>
#include "attestation.h"
#include "crypto.h"
#include "common/attestation_t.h"

#define PRINT_DISPATCH_MESSAGES 1
#define STATE_INIT 1
#define STATE_FETCH 2
#define STATE_UPDATE 3

using namespace std;

typedef struct _enclave_config_data
{
    uint8_t *enclave_secret_data;
    const char *other_enclave_public_key_pem;
    size_t other_enclave_public_key_pem_size;
} enclave_config_data_t;

typedef struct _state_info
{
    // TODO Key of attestation should write in this struct?
    uint8_t state[10000] = {0};
    // size_t state_size;
    uint8_t requests_I[512] = {0};
    // size_t requests_I_size;
    uint8_t ITHash[32];
} state_info_t;

class ecall_dispatcher
{
private:
    int m_initialized;
    Crypto *m_crypto;
    Attestation *m_attestation;
    string m_name;
    enclave_config_data_t *m_enclave_config;
    unsigned char m_other_enclave_signer_id[32];

public:
    ecall_dispatcher(const char *name, enclave_config_data_t *enclave_config);
    ~ecall_dispatcher();
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

    void print_peers();

    bool compare_rsa_key(
        uint8_t *rsa_public_key1,
        uint8_t *rsa_public_key2,
        size_t rsa_public_key_size);

    int rsa_encrypt_aes_key(
        uint8_t **encrypt_aes_data,
        size_t *encrypt_aes_data_size,
        uint8_t **mrenclave,
        size_t *mrenclave_size);

    int aes_encrypt_client_messages(
        uint8_t *requests_message,
        size_t requests_message_size,
        uint8_t **encrypt_data,
        size_t *encrypt_data_size,
        uint8_t **mrenclave,
        size_t *mrenclave_size);

    int aes_decrypt_server_messages(
        uint8_t *reply_data,
        size_t reply_data_size,
        size_t *is_ready);

    int aes_encrypt_ecdsa(
        uint8_t **encrypt_aes_data,
        size_t *encrypt_aes_data_size,
        uint8_t **mrenclave,
        size_t *mrenclave_size);

    int seal_state_data(
        int seal_policy,
        sealed_data_t **sealed_data,
        size_t *sealed_data_size);

    int unseal_state_data(
        const sealed_data_t *sealed_data,
        size_t sealed_data_size,
        unsigned char **data,
        size_t *data_size);
    int seal_state_data_host(
        uint8_t *requests_message,
        size_t requests_message_size,
        string status_message,
        uint8_t *ITHash);

private:
    bool initialize(const char *name);
};
