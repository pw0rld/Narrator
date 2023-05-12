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
#include <common/attestation_t.h>
#include <common/dispatcher.h>
#include <openenclave/enclave.h>

// For this purpose of this example: demonstrating how to do attestation
// g_enclave_secret_data is hardcoded as part of the enclave. In this sample,
// the secret data is hard coded as part of the enclave binary. In a real world
// enclave implementation, secrets are never hard coded in the enclave binary
// since the enclave binary itself is not encrypted. Instead, secrets are
// acquired via provisioning from a service (such as a cloud server) after
// successful attestation.
// The g_enclave_secret_data holds the secret data specific to the holding
// enclave, it's only visible inside this secured enclave. Arbitrary enclave
// specific secret data exchanged by the enclaves. In this sample, the first
// enclave sends its g_enclave_secret_data (encrypted) to the second enclave.
// The second enclave decrypts the received data and adds it to its own
// g_enclave_secret_data, and sends it back to the other enclave.

// TODO: remove the secret
uint8_t g_enclave_secret_data[ENCLAVE_SECRET_DATA_SIZE] =
    {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};

enclave_config_data_t config_data = {
    g_enclave_secret_data};

// Declare a static dispatcher object for enabling
// for better organizing enclave-wise global variables
static ecall_dispatcher dispatcher("Enclave1", &config_data);

int get_enclave_format_settings(
    const oe_uuid_t *format_id,
    uint8_t **format_settings,
    size_t *format_settings_size)
{
    return dispatcher.get_enclave_format_settings(
        format_id, format_settings, format_settings_size);
}

const char *enclave_name = "Enclave1";
/**
 * Return the public key of this enclave along with the enclave's
 * evidence. Another enclave can use the evidence to attest the enclave
 * and verify the integrity of the public key.
 */
int get_evidence_with_public_key(
    const oe_uuid_t *format_id,
    uint8_t *format_settings,
    size_t format_settings_size,
    uint8_t **pem_key,
    size_t *pem_key_size,
    uint8_t **evidence,
    size_t *evidence_size)
{
    return dispatcher.get_evidence_with_public_key(
        format_id,
        format_settings,
        format_settings_size,
        pem_key,
        pem_key_size,
        evidence,
        evidence_size);
}

// Attest and store the public key of another enclave.
int verify_evidence(
    const oe_uuid_t *format_id,
    uint8_t *pem_key,
    size_t pem_key_size,
    uint8_t *evidence,
    size_t evidence_size,
    size_t uuid)
{
    return dispatcher.verify_evidence(
        format_id, pem_key, pem_key_size, evidence, evidence_size, uuid);
}

int rsa_encrypt_aes_key(
    uint8_t **encrypt_aes_data,
    size_t *encrypt_aes_data_size,
    uint8_t **mrenclave,
    size_t *mrenclave_size)
{
    return dispatcher.rsa_encrypt_aes_key(encrypt_aes_data, encrypt_aes_data_size, mrenclave, mrenclave_size);
}

int aes_encrypt_client_messages(
    uint8_t *requests_message,
    size_t requests_message_size,
    uint8_t **encrypt_aes_data,
    size_t *encrypt_aes_data_size,
    uint8_t **mrenclave,
    size_t *mrenclave_size,
    int seal_size)
{
    return dispatcher.aes_encrypt_client_messages(requests_message, requests_message_size, encrypt_aes_data, encrypt_aes_data_size, mrenclave, mrenclave_size, seal_size);
}

int aes_decrypt_server_messages(
    uint8_t *reply_data,
    size_t reply_data_size,
    size_t *is_ready)
{
    return dispatcher.aes_decrypt_server_messages(reply_data, reply_data_size, is_ready);
}

int unseal_state_data(unsigned char *sealed_data, size_t sealed_data_size)
{
    return dispatcher.unseal_state_data(sealed_data, sealed_data_size);
}

int updateITHash(
    uint8_t *reply_data,
    size_t reply_data_size)
{

    return dispatcher.updateITHash(reply_data, reply_data_size);
}