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
#include "common/log.h"

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

int rsa_decrypt_verify_sig_and_set_aes(
    uint8_t *rsa_public_key,
    size_t rsa_public_key_size,
    uint8_t *encrypt_aes_data,
    size_t encrypt_aes_data_size,
    uint8_t *sig_aes_data,
    size_t sig_aes_data_size)
{
    return dispatcher.rsa_decrypt_verify_sig_and_set_aes(rsa_public_key, rsa_public_key_size, encrypt_aes_data, encrypt_aes_data_size, sig_aes_data, sig_aes_data_size);
}

int rsa_decrypt_client_aes(
    uint8_t *encrypt_aes_data,
    size_t encrypt_aes_data_size,
    uint8_t *mrenclave,
    size_t mrenclave_size,
    size_t uuid)
{
    return dispatcher.rsa_decrypt_client_aes(encrypt_aes_data, encrypt_aes_data_size, mrenclave, mrenclave_size, uuid);
}

int rsa_encrypt_and_sig_aes(
    uint8_t **rsa_public_key,
    size_t *rsa_public_key_size,
    uint8_t **encrypt_aes_data,
    size_t *encrypt_aes_data_size,
    uint8_t **sig_aes_data,
    size_t *sig_aes_data_size,
    size_t uuid)
{
    return dispatcher.rsa_encrypt_and_sig_aes(rsa_public_key, rsa_public_key_size, encrypt_aes_data, encrypt_aes_data_size, sig_aes_data, sig_aes_data_size, uuid);
}
int aes_encrypt_ecdsa(
    uint8_t **encrypt_aes_data,
    size_t *encrypt_aes_data_size,
    size_t uuid)
{
    return dispatcher.aes_encrypt_ecdsa(encrypt_aes_data, encrypt_aes_data_size, uuid);
}

int aes_decrypt_ecdsa_reply(
    uint8_t *encrypt_aes_data,
    size_t encrypt_aes_data_size,
    size_t uuid)
{
    return dispatcher.aes_decrypt_ecdsa_reply(encrypt_aes_data, encrypt_aes_data_size, uuid);
}

int aes_decrypt_client_messages(
    uint8_t *encrypt_aes_data,
    size_t encrypt_aes_data_size,
    uint8_t *mrenclave,
    size_t mrenclave_size,
    uint8_t **reply_data,
    size_t *reply_data_size,
    size_t client_id,
    size_t *reply_type)
{
    return dispatcher.aes_decrypt_client_messages(encrypt_aes_data, encrypt_aes_data_size, mrenclave, mrenclave_size, reply_data, reply_data_size, client_id, reply_type);
}
// Sign message for another enclave using ecdsa
int ecdsa_sign_message(
    int policy,
    uint8_t *data,
    size_t data_size,
    uint8_t **sig,
    size_t *sig_size)
{
    return dispatcher.ecdsa_sign_message(policy, data, data_size, sig, sig_size);
}

// verify sign for another enclave use ecdsa
int ecdsa_verify_sign_message(
    uint8_t *data,
    size_t data_size,
    uint8_t *sig_data,
    size_t sig_data_size,
    uint8_t *ecdsa_key,
    size_t ecdsa_key_size)
{
    return dispatcher.ecdsa_verify_sign_message(data, data_size, sig_data, sig_data_size, ecdsa_key, ecdsa_key_size);
}

int LedgerRead_key(uint8_t **publickey_id, size_t *publickey_id_size, uint8_t **sgx_uid, size_t *sgx_uid_size)
{
    return dispatcher.LedgerRead_key(publickey_id, publickey_id_size, sgx_uid, sgx_uid_size);
}

int LedgerRead_other_key(uint8_t **publickey_id, size_t *publickey_id_size, uint8_t **sgx_uid, size_t *sgx_uid_size, size_t uuid)
{
    return dispatcher.LedgerRead_other_key(publickey_id, publickey_id_size, sgx_uid, sgx_uid_size, uuid);
}

int create_kpi_certificate_ecall(
    uint8_t **pki_certificate,
    size_t *pki_certificate_size,
    size_t uuid)
{
    return dispatcher.create_kpi_certificate_ecall(pki_certificate, pki_certificate_size, uuid);
}

int process_kpi_certificate_ecall(
    uint8_t *pki_certificate,
    size_t pki_certificate_size,
    size_t uuid)
{
    return dispatcher.process_kpi_certificate_ecall(pki_certificate, pki_certificate_size, uuid);
}
int verify_ed25519(uint8_t *signture, size_t signture_size, uint8_t *source_text, size_t source_text_size)
{
    return dispatcher.verify_ed25519(signture, signture_size, source_text, source_text_size);
}

void set_uuid_ecall(size_t uuid)
{
    return dispatcher.set_uuid_ecall(uuid);
}

int seal_state_data(
    int sealPolicy,
    sealed_data_t **sealed_data,
    size_t *sealed_data_size)
{
    return dispatcher.seal_state_data(sealPolicy, sealed_data, sealed_data_size);
}

// int unseal_state_data(
//     sealed_data_t *sealed_data,
//     size_t sealed_data_size,
//     unsigned char **data,
//     size_t *data_size)
// {
//     return dispatcher.unseal_state_data(sealed_data, sealed_data_size, data, data_size);
// }

// INFO ROTE
int updateLocalASECounterTable(size_t AE_uuid, uint8_t *ITHash, size_t ITHash_size)
{
    // return 0;
    return dispatcher.updateLocalASECounterTable(AE_uuid, ITHash, ITHash_size);
}

int ecdsa_signed( // INFO ROTE
    size_t AE_uuid,
    int policy,
    unsigned char **signed_data,
    size_t *signed_data_size,
    unsigned char **encrypt_data,
    size_t *encrypt_data_size)
{
    return dispatcher.ecdsa_signed(AE_uuid, policy, signed_data, signed_data_size, encrypt_data, encrypt_data_size);
}

int verify( // INFO ROTE
    size_t AE_uuid,
    int policy,
    unsigned char *sig_data,
    size_t sig_data_size,
    unsigned char *encrypt_data,
    size_t encrypt_data_size)
{
    // return 0;
    return dispatcher.verify(AE_uuid, policy, sig_data, sig_data_size, encrypt_data, encrypt_data_size);
}

// INFO ROTE
int signed_with_verify(size_t uuid,
                       int policy,
                       unsigned char *sig_data,
                       size_t sig_data_size,
                       unsigned char *encrypt_data,
                       size_t encrypt_data_size,
                       int signed_policy,
                       unsigned char **signed_data,
                       size_t *signed_data_size,
                       unsigned char **encrypt_data_out,
                       size_t *encrypt_data_out_size)
{
    return dispatcher.signed_with_verify(uuid, policy, sig_data, sig_data_size, encrypt_data, encrypt_data_size,
                                         signed_policy, signed_data, signed_data_size, encrypt_data_out, encrypt_data_out_size);
}