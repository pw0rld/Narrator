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

#include "dispatcher.h"
#include <chrono>
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/advanced/mallinfo.h>

#include <openenclave/enclave.h>

#include <openssl/ecdsa.h>
#include <openssl/ecdh.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/pem.h>

// transfer uint8 to string
std::string uint8_to_hex_string(const uint8_t *v, const size_t s)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < s; i++)
    {
        ss << std::hex << std::setw(2) << static_cast<int>(v[i]);
    }
    return ss.str();
}

// transfer string to uint8,and save results in vector
std::vector<uint8_t> hex_string_to_uint8_vec(const string &hex)
{
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 2)
    {
        string byteString = hex.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteString.c_str(), nullptr, 16);
        bytes.push_back(byte);
    }
    return bytes;
}

int64_t print_time()
{

    std::chrono::milliseconds ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    return ms.count();
}

static size_t _get_heap_size()
{
    oe_mallinfo_t info;
    oe_result_t rc = oe_allocator_mallinfo(&info);
    return info.current_allocated_heap_size;
}

/**
 * @brief transfer sting that contains ascii synmbols to uint8
 * @param hex
 * @return std::vector<uint8_t>
 */
std::vector<uint8_t> hex_string_to_uint8_vec_version2(const string &hex)
{
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 1)
    {
        int tmp = hex[i] - 0;
        uint8_t byte = tmp;
        bytes.push_back(byte);
    }
    return bytes;
}

std::string uint8_to_hex_string_version2(const uint8_t *v, const size_t s)
{
    std::stringstream ss;
    for (int i = 0; i < s; i += 1)
    {
        ss << std::hex << std::setw(1) << v[i];
    }
    return ss.str();
}

/**
 * @brief split the input string
 * @param str
 * @param delim
 * @return vector<string>
 */
vector<string> split(const string &str, const string &delim)
{
    vector<string> ret;
    if ("" == str)
        return ret;
    // covert string to char array
    char *strs = new char[str.length() + 1];
    strcpy(strs, str.c_str());

    char *d = new char[delim.length() + 1];
    strcpy(d, delim.c_str());

    char *p = strtok(strs, d);
    while (p)
    {
        string s = p;
        ret.push_back(s);
        p = strtok(NULL, d);
    }
    oe_free(strs);
    strs = NULL;
    oe_free(d);
    d = NULL;
    oe_free(p);
    p = NULL;
    return ret;
}

/**
 * @brief init ecall_dispatcher
 * @param name
 * @param enclave_config
 */
ecall_dispatcher::ecall_dispatcher(
    const char *name,
    enclave_config_data_t *enclave_config)
    : m_crypto(nullptr), m_attestation(nullptr)
{
    m_enclave_config = enclave_config;
    m_initialized = initialize(name);
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

int ecall_dispatcher::initialize(const char *name)
{
    int ret = 1;
    uint8_t *report;
    size_t report_size = 0;
    size_t other_enclave_signer_id_size = 0;
    oe_result_t result = OE_OK;
    oe_report_t parsed_report = {0};
    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == nullptr)
    {
        ret = 1;
        return ret;
    }

    other_enclave_signer_id_size = sizeof(m_enclave_signer_id);
    result = oe_get_report_v2(0, NULL, 0, NULL, 0, &report, &report_size); // obtain my mrenclave
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("Error: oe_get_report_v2 failed.(%s)", oe_result_str(result));
        ret = 1;
        return ret;
    }

    result = oe_parse_report(report, report_size, &parsed_report);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("Error: oe_get_evidence failed.(%s)", oe_result_str(result));
        ret = 1;
        return ret;
    }
    memcpy(m_enclave_signer_id, parsed_report.identity.unique_id, 32);

    m_attestation = new Attestation(m_crypto, m_enclave_signer_id);
    if (m_attestation == nullptr)
    {
        TRACE_ENCLAVE("Error: init attestation failed.(%s)", oe_result_str(result));
        ret = 1;
        return ret;
    }
    batch_queue_decrypt.reserve(sizeof(Ae_queues_decrypt) * 10);
    ret = 0;

    oe_free(report);
    report = NULL;
    return ret;
}

/********************* attestation funtions *******************************/
/**
 * @brief obtain encalve's format_setting
 * @param format_id local or remote attestation
 * @param format_settings_buffer the buffer for storing format_setting
 * @param format_settings_buffer_size
 * @return success: 0  failure: 1
 */
int ecall_dispatcher::get_enclave_format_settings(
    const oe_uuid_t *format_id,
    uint8_t **format_settings_buffer,
    size_t *format_settings_buffer_size)
{
    uint8_t *format_settings = nullptr;
    size_t format_settings_size = 0;
    int ret = 1;

    if (m_initialized != 0)
    {
        TRACE_ENCLAVE("Error: ecall_dispatcher initialization failed");
        ret = 1;
        return ret;
    }

    // Generate a format settings so that the enclave that receives this format
    // settings can attest this enclave.
    if (PRINT_DISPATCH_MESSAGES)
    {
        // TRACE_ENCLAVE("Dispatcher Info: get_enclave_format_settings");
    }

    if (m_attestation->get_format_settings(
            format_id, &format_settings, &format_settings_size) == false)
    {
        TRACE_ENCLAVE("Error: get_enclave_format_settings failed");
        ret = 1;
        return ret;
    }

    if (format_settings && format_settings_size)
    {
        // Allocate memory on the host and copy the format settings over.
        // enclave can directly write into host memory
        *format_settings_buffer =
            (uint8_t *)oe_host_malloc(format_settings_size);
        if (*format_settings_buffer == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            TRACE_ENCLAVE("Error: copying format_settings failed, out of memory");
            ret = 1;
            return ret;
        }
        memcpy(*format_settings_buffer, format_settings, format_settings_size);
        *format_settings_buffer_size = format_settings_size;
        oe_verifier_free_format_settings(format_settings);
    }
    else
    {
        *format_settings_buffer = nullptr;
        *format_settings_buffer_size = 0;
    }
    ret = 0;

exit:
    oe_free(format_settings);
    format_settings = NULL;
    if (ret != 0)
        TRACE_ENCLAVE("Error: get_enclave_format_settings failed.");
    return ret;
}

/**
 * @brief Generate attestation evidence and one pair of rsa keys
 * @param format_id
 * @param format_settings
 * @param format_settings_size
 * @param pem_key
 * @param pem_key_size
 * @param evidence_buffer
 * @param evidence_buffer_size
 * @return success: 0 failure 1
 */
int ecall_dispatcher::get_evidence_with_public_key(
    const oe_uuid_t *format_id,
    uint8_t *format_settings,
    size_t format_settings_size,
    uint8_t **pem_key,
    size_t *pem_key_size,
    uint8_t **evidence_buffer,
    size_t *evidence_buffer_size)
{
    uint8_t m_rsa_public_key[512];
    uint8_t *evidence = nullptr;
    size_t evidence_size = 0;
    uint8_t *key_buffer = nullptr;
    int ret = 1;

    if (PRINT_DISPATCH_MESSAGES)
    {
        // TRACE_ENCLAVE("Dispatcher Enter: get_evidence_with_public_key");
    }

    if (m_initialized != 0)
    {
        TRACE_ENCLAVE("Error: ecall_dispatcher initialization failed.");
        ret = 1;
        return ret;
        ;
    }

    m_crypto->copy_rsa_public_key(m_rsa_public_key);
    // Generate evidence for the public key so that the enclave that receives the key can attest this enclave.
    if (m_attestation->generate_attestation_evidence(
            format_id,
            format_settings,
            format_settings_size,
            m_rsa_public_key,
            sizeof(m_rsa_public_key),
            &evidence,
            &evidence_size) == false)
    {

        TRACE_ENCLAVE("Error: get_evidence_with_public_key failed");
        ret = 1;
        return ret;
        ;
    }
    // Allocate memory on the host and copy the evidence over.
    // enclave can directly write into host memory
    *evidence_buffer = (uint8_t *)oe_host_malloc(evidence_size);
    if (*evidence_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("Error: copying evidence_buffer failed, out of memory");
        ret = 1;
        return ret;
        ;
    }
    memcpy(*evidence_buffer, evidence, evidence_size);
    *evidence_buffer_size = evidence_size;
    oe_free_evidence(evidence);
    // ALLocate memory on the host and copy the ecdsa public key
    key_buffer = (uint8_t *)oe_host_malloc(512);
    if (key_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("Error: copying key_buffer failed, out of memory");
        ret = 1;
        return ret;
        ;
    }
    // m_crypto->copy_rsa_public_key(key_buffer);
    memcpy(key_buffer, m_rsa_public_key, sizeof(m_rsa_public_key));
    *pem_key = key_buffer;
    *pem_key_size = sizeof(m_rsa_public_key);

    ret = 0;
    if (PRINT_DISPATCH_MESSAGES)
    {
        // TRACE_ENCLAVE("Dispatcher Info: get_evidence_with_public_key succeeded");
    }

exit:
    if (ret != 0)
    {
        if (evidence)
            oe_free_evidence(evidence);
        if (key_buffer)
            oe_host_free(key_buffer);
        if (*evidence_buffer)
            oe_host_free(*evidence_buffer);
    }
    evidence = NULL;
    key_buffer = NULL;
    return ret;
}

/**
 * @brief verify receiving local or remote evidence and set rsa public key
 * @param format_id
 * @param pem_key rsa的public key
 * @param pem_key_size
 * @param evidence
 * @param evidence_size
 * @return Success: 0  Failure: 1
 */
int ecall_dispatcher::verify_evidence(
    const oe_uuid_t *format_id,
    uint8_t *pem_key,
    size_t pem_key_size,
    uint8_t *evidence,
    size_t evidence_size,
    size_t uuid)
{
    int ret = 1;

    // create the new peer
    peer_info_t pr;
    vector<peer_info_t>::iterator it;

    if (m_initialized != 0)
    {
        TRACE_ENCLAVE("Error: ecall_dispatcher initialization failed.");
        ret = 1;
        return ret;
        ;
    }

    // Attest the evidence and accompanying key.
    if (m_attestation->attest_attestation_evidence(format_id, evidence, evidence_size, pem_key, pem_key_size) == false)
    {
        TRACE_ENCLAVE("Error: verify_evidence_and_set_public_key failed.");
        ret = 1;
        return ret;
        ;
    }

    // check whether the peer exists
    // uuid 没对应上
    it = std::find(peer_info_vec2.begin(), peer_info_vec2.end(), uuid);
    if (it != peer_info_vec2.end())
    {
        memcpy((*it).rsa_public_key, pem_key, 512);
        (*it).rsa_key_size = 512;
        TRACE_ENCLAVE("Warning: Peer already exists.And uuid is %d", uuid);
        ret = 1;
        return ret;
    }

    memcpy(pr.rsa_public_key, pem_key, pem_key_size);
    pr.uuid = uuid;
    pr.rsa_key_size = pem_key_size;
    peer_info_vec2.push_back(pr);
    if (PRINT_DISPATCH_MESSAGES)
    {
        TRACE_ENCLAVE("Dispatcher Info: verify_evidence_and_set_public_key succeeded.The uuid is %zu", uuid);
        // print_peers();
    }
    ret = 0;

exit:
    return ret;
}

/********************* attestation funtions *******************************/
/**
 * @brief use receiver's rea pk to encrypt aes key, and sign it by my sk
 * @param rsa_public_key
 * @param encrypt_aes_data
 * @param encrypt_aes_data_size
 * @param sig_aes_data
 * @param sig_aes_data_size
 * @return int
 */
int ecall_dispatcher::rsa_encrypt_and_sig_aes(
    uint8_t **rsa_public_key,
    size_t *rsa_public_key_size,
    uint8_t **encrypt_aes_data,
    size_t *encrypt_aes_data_size,
    uint8_t **sig_aes_data,
    size_t *sig_aes_data_size,
    size_t uuid)
{
    int ret = 1;
    uint8_t encrypt_data[1024];
    memset(encrypt_data, 0, sizeof(encrypt_data));
    size_t encrypt_data_size;
    uint8_t sig_data[1024];
    size_t sig_data_size;
    uint8_t m_aes_key[128];
    uint8_t m_rsa_public_key[512];
    // uint8_t aes_key_and_iv[144]; // 128 AES key + 16 AES IV
    vector<peer_info_t>::iterator it;

    // check whether the peer exists
    it = std::find(peer_info_vec2.begin(), peer_info_vec2.end(), uuid);
    if (it == peer_info_vec2.end())
    {
        TRACE_ENCLAVE("Error: generate ase fialed, peer doesn't exists.");
        // print_peers();
        ret = 1;
        return ret;
        ;
    }

    // TODO: In future version, init a new aes key for each peer
    // update aes key with the peer
    m_crypto->copy_rsa_public_key(m_rsa_public_key);
    m_crypto->copy_aes_key(m_aes_key);
    (*it).aes_key_size = sizeof(m_aes_key);
    memcpy((*it).aes_key, m_aes_key, sizeof(m_aes_key));

    memcpy(Re_persistent_state_table.m_aes_key, m_aes_key, sizeof(m_aes_key));

    // test the aes encryption scheme
    ret = m_crypto->rsa_encrypt((*it).rsa_public_key, (*it).rsa_key_size, m_aes_key, sizeof(m_aes_key), encrypt_data, &encrypt_data_size);

    // use the receiver rsa public key to encrypt aes secret key
    if (ret != 0)
    {
        TRACE_ENCLAVE("Dispatcher Info: encrypt aes key failed.");
        ret = 1;
        return ret;
    }
    else
    {
        *encrypt_aes_data = (uint8_t *)oe_host_malloc(encrypt_data_size);
        if (*encrypt_aes_data == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            TRACE_ENCLAVE("Error: copying encrypt_ecdsa_data failed, out of memory");
            ret = 1;
            return ret;
            ;
        }
        memcpy(*encrypt_aes_data, encrypt_data, encrypt_data_size);
        *encrypt_aes_data_size = encrypt_data_size;
    }

    // use my rsa secret key to sign the data
    ret = m_crypto->rsa_sign(encrypt_data, encrypt_data_size, sig_data, &sig_data_size);
    if (ret == 0)
    {
        *sig_aes_data = (uint8_t *)oe_host_malloc(sig_data_size);
        if (*sig_aes_data == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            TRACE_ENCLAVE("Error: copying encrypt_ecdsa_data failed, out of memory");
            ret = 1;
            return ret;
            ;
        }
        memcpy(*sig_aes_data, sig_data, sig_data_size);
        *sig_aes_data_size = sig_data_size;
    }
    else
    {
        TRACE_ENCLAVE("Dispatcher Info: rsa_sign aes key failed.");
        ret = 1;
        return ret;
        ;
    }

    // output the signning key
    *rsa_public_key = (uint8_t *)oe_host_malloc(sizeof(m_rsa_public_key));
    memcpy(*rsa_public_key, m_rsa_public_key, sizeof(m_rsa_public_key));
    *rsa_public_key_size = sizeof(m_rsa_public_key);

    if (PRINT_DISPATCH_MESSAGES)
    {
        // TRACE_ENCLAVE("Dispatcher Info: Generate AES key succeeded.");
    }
    ret = 0;
exit:
    return ret;
}

/**
 * @brief verify rsa signature and deencrypt the data to obtain aes key
 * @param rsa_public_key           //sender's rsa key
 * @param rsa_public_key_size
 * @param encrypt_aes_data         //encrypted data containing aes key
 * @param encrypt_aes_data_size
 * @param sig_aes_data             //sender's signature
 * @param sig_aes_data_size
 * @return int 0 Success  1 Failed
 */
int ecall_dispatcher::rsa_decrypt_verify_sig_and_set_aes(
    uint8_t *rsa_public_key,
    size_t rsa_public_key_size,
    uint8_t *encrypt_aes_data,
    size_t encrypt_aes_data_size,
    uint8_t *sig_aes_data,
    size_t sig_aes_data_size)
{
    int ret = 1;
    uint8_t decrypt_data[1024];
    memset(decrypt_data, 0, sizeof(decrypt_data));
    size_t decrypt_data_size;
    uint8_t sig_data[1024];
    size_t sig_data_size;
    client_info pr;
    vector<peer_info_t>::iterator it;

    ret = m_crypto->rsa_verify(rsa_public_key, rsa_public_key_size, encrypt_aes_data, encrypt_aes_data_size, sig_aes_data, sig_aes_data_size);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Error: rsa_verify_sig failed!");
        ret = 1;
        return ret;
        ;
    }

    ret = m_crypto->rsa_decrypt(encrypt_aes_data, encrypt_aes_data_size, decrypt_data, &decrypt_data_size);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Dispatch Info: RSA_decrypt failed!");
        ret = 1;
        return ret;
        ;
    }
    else
    {
        TRACE_ENCLAVE("Dispatch Info: RSA_decrypt succeed!Size is %zu AES key is %s", decrypt_data_size, decrypt_data);
    }

    for (it = peer_info_vec2.begin(); it != peer_info_vec2.end(); ++it)
    {
        if (compare_key((*it).rsa_public_key, rsa_public_key, rsa_public_key_size) == true)
        {
            memcpy((*it).aes_key, decrypt_data, 128);
            (*it).aes_key_size = 128;
            TRACE_ENCLAVE("Dispatch Info: RSA_decrypt succeed!");
            break;
        }
    }
    // TRACE_ENCLAVE("Dispatch Info: RSA_decrypt succeed!");
    if (it == peer_info_vec2.end())
    {
        TRACE_ENCLAVE("Error: The input rsa public key doesn't exists.");
        ret = 1;
        return ret;
        ;
    }
    ret = 0;
    // TRACE_ENCLAVE("Dispatch Info: RSA_decrypt succeed!");
exit:
    return ret;
}

/**
 * @brief Generate ECDSA and use AES to encrypt
 * @param encrypt_aes_data  encrypted data
 * @param encrypt_aes_data_size
 * @param
 * @param sig_aes_data_size
 * @return int
 */
int ecall_dispatcher::aes_encrypt_ecdsa(
    uint8_t **encrypt_aes_data,
    size_t *encrypt_aes_data_size,
    size_t uuid)
{
    int ret = 1;
    uint8_t encrypt_data[2048];
    uint8_t m_ecdsa_public_key[256];
    memset(m_ecdsa_public_key, 0, sizeof(m_ecdsa_public_key));
    uint8_t m_ecdsa_private_key[256];
    memset(m_ecdsa_private_key, 0, sizeof(m_ecdsa_private_key));
    size_t encrypt_data_size = 0;
    vector<peer_info_t>::iterator it;
    // check whether the peer exists
    it = std::find(peer_info_vec2.begin(), peer_info_vec2.end(), uuid);
    if (it == peer_info_vec2.end())
    {
        TRACE_ENCLAVE("Error: generate ase fialed, peer doesn't exists.");
        // print_peers();
        ret = 1;
        return ret;
        ;
    }
    m_crypto->copy_ecdsa_pubkey_key(m_ecdsa_public_key);
    m_crypto->copy_ecdsa_pri_key(m_ecdsa_private_key); // INFO ROTE

    memcpy(Re_persistent_state_table.m_aes_key, (*it).aes_key, 128);               // INFO ROTE
    memcpy(Re_persistent_state_table.m_ecdsa_public_key, m_ecdsa_public_key, 256); // INFO ROTE
    memcpy(Re_persistent_state_table.m_ecdsa_private_key, m_ecdsa_private_key, sizeof(m_ecdsa_private_key));
    // Use aes key to encrypt the ecdsa public key
    ret = m_crypto->aes_encrypt(m_ecdsa_public_key, sizeof(m_ecdsa_public_key), encrypt_data, &encrypt_data_size, (*it).aes_key);

    if (ret != 0)
    {
        TRACE_ENCLAVE("Error: aes_encrypt failed!");
        ret = 1;
        return ret;
        ;
    }

    *encrypt_aes_data = (uint8_t *)oe_host_malloc(encrypt_data_size);
    if (*encrypt_aes_data == NULL)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("aes_encrypt Error: copying encrypt_ecdsa_data failed, out of memory");
        ret = 1;
        return ret;
        ;
    }
    memcpy(*encrypt_aes_data, encrypt_data, encrypt_data_size);
    *encrypt_aes_data_size = encrypt_data_size;

    if (PRINT_DISPATCH_MESSAGES)
    {
        TRACE_ENCLAVE("Dispatcher Info: aes_encrypt ecdsa pub key succeeded.");
    }
    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::aes_decrypt_ecdsa_reply(
    uint8_t *encrypt_aes_data,
    size_t encrypt_aes_data_size,
    size_t uuid)
{
    int ret = 1;
    uint8_t *decrypt_data;
    size_t decrypt_data_size;
    decrypt_data = (uint8_t *)malloc(encrypt_aes_data_size + 128);
    vector<peer_info_t>::iterator it;
    it = std::find(peer_info_vec2.begin(), peer_info_vec2.end(), uuid);
    if (it == peer_info_vec2.end())
    {
        TRACE_ENCLAVE("Error: process ecdsa-reply fialed, peer doesn't exists.uuid is %zu", uuid);
        print_peers();
        ret = 1;
        return ret;
        ;
    }

    ret = m_crypto->aes_decrypt(encrypt_aes_data, encrypt_aes_data_size, decrypt_data, &decrypt_data_size, (*it).aes_key);
    if (ret == 0)
    {
        memcpy((*it).ecdsa_public_key, decrypt_data, 256);
        (*it).ecdsa_key_size = 256;
    }
    else
    {
        TRACE_ENCLAVE("Error: aes decrypt failed!");
        ret = 1;
        return ret;
        ;
    }
    ret = 0;
exit:
    oe_free(decrypt_data);
    decrypt_data = NULL;
    return ret;
}

/**
 * @brief create ecdsa pki
 * @param pki_certificate
 * @param pki_certificate_size
 * @return int 0 success 1 failure
 */
int ecall_dispatcher::create_kpi_certificate_ecall(
    uint8_t **pki_certificate,
    size_t *pki_certificate_size,
    size_t uuid)
{
    string message;
    string tmp;
    int ret = 1;
    uint8_t m_aes_key[128];
    m_crypto->copy_aes_key(m_aes_key);
    uint8_t *aes_encrypt_msg;
    uint8_t m_ecdsa_key[256];
    size_t aes_encrypt_msg_size;
    std::vector<uint8_t> marge_message_vec;
    vector<peer_info_t>::iterator it;
    // search for the uuid
    it = std::find(peer_info_vec2.begin(), peer_info_vec2.end(), uuid);
    if (it == peer_info_vec2.end())
    {
        TRACE_ENCLAVE("Error: generate pki fialed, peer doesn't exists.uuid is %zu", uuid);
        print_peers();
        ret = 1;
        return ret;
        ;
    }
    for (vector<peer_info_t>::iterator iter = peer_info_vec2.begin(); iter != peer_info_vec2.end(); ++iter)
    {
        tmp = uint8_to_hex_string((*iter).ecdsa_public_key, (*iter).ecdsa_key_size);
        message += "#" + to_string((*iter).uuid) + "@" + tmp + "!";
    }

    m_crypto->copy_ecdsa_pubkey_key(m_ecdsa_key);
    tmp = uint8_to_hex_string(m_ecdsa_key, sizeof(m_ecdsa_key));
    message += "#" + to_string(m_crypto->get_my_uuid()) + "@" + tmp + "!";
    marge_message_vec = hex_string_to_uint8_vec_version2(message);
    aes_encrypt_msg = (uint8_t *)malloc(marge_message_vec.size() + 128);
    memset(aes_encrypt_msg, 0, marge_message_vec.size() + 128);
    ret = m_crypto->aes_encrypt(&marge_message_vec[0], marge_message_vec.size(), aes_encrypt_msg, &aes_encrypt_msg_size, m_aes_key);
    if (ret != 0)
    {
        TRACE_ENCLAVE("create_kpi_certificate_ecall failed.");
        ret = 1;
        return ret;
        ;
    }
    TRACE_ENCLAVE("aes_encrypt_msg_size is %zu ", aes_encrypt_msg_size);

    *pki_certificate = (uint8_t *)oe_host_malloc(aes_encrypt_msg_size);
    if (*pki_certificate == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("copying sig_host_buffer failed, out of memory");
        ret = 1;
        return ret;
        ;
    }
    memcpy(*pki_certificate, aes_encrypt_msg, aes_encrypt_msg_size);
    *pki_certificate_size = aes_encrypt_msg_size;
    ret = 0;
    TRACE_ENCLAVE("create_kpi_certificate_ecall Success!\n.");
exit:
    oe_free(aes_encrypt_msg);
    aes_encrypt_msg = NULL;
    return ret;
}

/**
 * @brief process the received pki certificate
 * @param pki_certificate
 * @param pki_certificate_size
 * @return int
 */
int ecall_dispatcher::process_kpi_certificate_ecall(
    uint8_t *pki_certificate,
    size_t pki_certificate_size,
    size_t uuid)
{
    string tmp;
    int ret = 1;
    uint8_t *decrypt_data;
    decrypt_data = (uint8_t *)malloc(pki_certificate_size + 128);
    memset(decrypt_data, 0, sizeof(pki_certificate_size + 128));
    size_t decrypt_data_size;
    vector<std::string> sp;
    vector<size_t> positions;
    size_t pos;
    size_t pos_h = 0;
    peer_info_t pr = {};
    peer_info_t prb = {};
    size_t peer_uuid;
    vector<peer_info_t>::iterator it;
    vector<peer_info_t>::iterator iter;
    std::vector<uint8_t> marge_message_vec;
    // search for the uuid
    it = std::find(peer_info_vec2.begin(), peer_info_vec2.end(), uuid);
    if (it == peer_info_vec2.end())
    {
        TRACE_ENCLAVE("Error: process pki fialed, peer doesn't exists.");
        ret = 1;
        return ret;
        ;
    }

    ret = m_crypto->aes_decrypt(pki_certificate, pki_certificate_size, decrypt_data, &decrypt_data_size, (*it).aes_key);
    if (ret != 0)
    {
        TRACE_ENCLAVE("verify ase decrypt failed!");
        ret = 1;
        return ret;
        ;
    }
    TRACE_ENCLAVE("pki_certificate_size size is %zu and decrypt size is %zu", pki_certificate_size, decrypt_data_size);
    tmp = uint8_to_hex_string_version2(decrypt_data, decrypt_data_size);
    pos_h = tmp.find("#");
    TRACE_ENCLAVE("tmp decrypt is %s", tmp.c_str());
    if (pos_h != 0 || pos_h == string::npos)
    {
        TRACE_ENCLAVE("Can not find the start symbol #.The decrypt_data_size is %zu", decrypt_data_size);
        ret = 1;
        return ret;
        ;
    }
    pos = tmp.find("#");
    while (pos != string::npos)
    {
        positions.push_back(pos);
        pos = tmp.find("#", pos + 1);
    }
    positions.push_back(tmp.size() + 1);
    for (int p = 0; p < positions.size() - 1; p++)
    {
        string w = tmp.substr(positions[p], positions[p + 1] - positions[p]);
        pos = w.find("!");
        if (pos == w.npos)
        {
            TRACE_ENCLAVE("can not find the end symbol!");
            return ret;
            ;
        }
        else
        {
            w.erase(pos);
        }
        w.erase(w.begin());
        TRACE_ENCLAVE("string is %s", w.c_str());
        sp = split(w, "@");
        if (sp.size() < 1)
        {
            TRACE_ENCLAVE("split pki_certificate failed");
            ret = 1;
            return ret;
            ;
        }
        peer_uuid = static_cast<size_t>(stoi(sp[0]));
        if (m_crypto->get_my_uuid() == peer_uuid)
        {
            continue;
        }
        marge_message_vec = hex_string_to_uint8_vec(sp[1]);
        iter = std::find(peer_info_vec2.begin(), peer_info_vec2.end(), peer_uuid);
        if (iter != peer_info_vec2.end())
        {
            prb.uuid = peer_uuid;
            memcpy(prb.ecdsa_public_key, &marge_message_vec[0], marge_message_vec.size());
            prb.ecdsa_key_size = marge_message_vec.size();
            memcpy(prb.aes_key, (*it).aes_key, 128);
            peer_info_vec2.push_back(prb);
            memcpy((*iter).ecdsa_public_key, &marge_message_vec[0], marge_message_vec.size());
            (*iter).ecdsa_key_size = marge_message_vec.size();
        }
        else
        {
            pr.uuid = peer_uuid;
            memcpy(pr.ecdsa_public_key, &marge_message_vec[0], marge_message_vec.size());
            pr.ecdsa_key_size = marge_message_vec.size();
            memcpy(pr.aes_key, (*it).aes_key, 128);
            pr.aes_key_size = 128;
            peer_info_vec2.push_back(pr);
        }
    }
    // print_peers();
    free(decrypt_data);
    decrypt_data = NULL;
    ret = 0;
exit:
    return ret;
}

void ecall_dispatcher::set_uuid_ecall(size_t uuid)
{
    m_crypto->set_my_uuid(uuid);
}

/**
 * @brief use ecdsa sk to sign message
 * @param data
 * @param data_size
 * @param sig
 * @param sig_size
 * @return int
 */
int ecall_dispatcher::ecdsa_sign_message(
    int policy,
    uint8_t *data,
    size_t data_size,
    uint8_t **sig,
    size_t *sig_size)
{
    int ret = 1;
    uint8_t *sig_host_buffer;
    uint8_t sig_buffer[512] = {0};
    size_t sig_host_size;
    size_t sig_buffer_size;
    if (m_initialized != 0)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        ret = 1;
        return ret;
        ;
    }
    if (m_crypto->ecdsa_signed_openssl(data, data_size, sig_buffer, &sig_host_size) != 0)
    {
        TRACE_ENCLAVE("enclave: ecdsa_sign failed");
        ret = 1;
        return ret;
        ;
    }
    if (policy == 1)
    {
        sig_host_buffer = (uint8_t *)oe_host_malloc(sig_host_size);
        if (sig_host_buffer == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            TRACE_ENCLAVE("copying sig_host_buffer failed, out of memory");
            ret = 1;
            return ret;
            ;
        }
        memcpy(sig_host_buffer, sig_buffer, sig_host_size);
        *sig = sig_host_buffer;
        *sig_size = sig_host_size;
    }
    else
    {
        sig_host_buffer = (uint8_t *)malloc(sig_host_size);
        memcpy(sig_host_buffer, sig_buffer, sig_host_size);
        *sig = sig_host_buffer;
        *sig_size = sig_host_size;
    }
    ret = 0;

exit:
    oe_free(sig_host_buffer);
    sig_host_buffer = NULL;
    return ret;
}

/**
 * @brief verify the signature by ecdsa
 * @param data
 * @param data_size
 * @param sig_data
 * @param sig_data_size
 * @return int
 */
int ecall_dispatcher::ecdsa_verify_sign_message(
    uint8_t *data,
    size_t data_size,
    uint8_t *sig_data,
    size_t sig_data_size,
    uint8_t *ecdsa_key,
    size_t ecdsa_key_size)
{
    int ret = 1;
    if (m_initialized != 0)
    {
        TRACE_ENCLAVE("ecall_dispatcher initialization failed");
        ret = 1;
        return ret;
        ;
    }
    if (m_crypto->ecdsa_verify_openssl(data, data_size, sig_data, sig_data_size, ecdsa_key, ecdsa_key_size) != 0)
    {
        TRACE_ENCLAVE("Encalve:ecdsa_verify_sign failed");
        ret = 1;
        return ret;
        ;
    }
    else
    {
        TRACE_ENCLAVE("ecdsa_verify_sign Success");
    }
    ret = 0;
exit:
    return ret;
}

/********************* funtions with AE client*******************************/
/**
 * @brief decrypt aes key from AE
 * @param rsa_public_key           //sender's rsa key
 * @param rsa_public_key_size
 * @param encrypt_aes_data         //encrypted data containing aes key
 * @param encrypt_aes_data_size
 * @param sig_aes_data             //sender's signature
 * @param sig_aes_data_size
 * @return int 0 Success  1 Failed
 */
int ecall_dispatcher::rsa_decrypt_client_aes(
    uint8_t *encrypt_aes_data,
    size_t encrypt_aes_data_size,
    uint8_t *mrenclave,
    size_t mrenclave_size,
    size_t uuid)
{
    int ret = 1;
    uint8_t decrypt_data[2048];
    size_t decrypt_data_size = sizeof(decrypt_data);
    client_info pr;
    vector<client_info>::iterator it;
    Local_AE_counter_table local_table; // INFO ROTE
    local_table.ASE_uuid = uuid;
    ret = m_crypto->rsa_decrypt(encrypt_aes_data, encrypt_aes_data_size, decrypt_data, &decrypt_data_size);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Dispatch Info: rsa_decrypt failed!");
        ret = 1;
        return ret;
        ;
    }
    else
    {
        TRACE_ENCLAVE("Dispatch Info: rsa_decrypt succeed!");
    }
    memcpy(local_table.m_aes_key, decrypt_data, decrypt_data_size); // info rote
    Re_persistent_state_table.local_aes.push_back(local_table);     // INFO ROTE

    for (it = client_info_vec.begin(); it != client_info_vec.end(); ++it)
    {
        // compare the mrenclave
        if (compare_key((*it).mrenclave, mrenclave, 32) == true) //
        {
            // update the aes key
            memcpy((*it).aes_key, decrypt_data, 128);
            TRACE_ENCLAVE("Dispatch Info: local update success");
            break;
        }
    }
    if (it == client_info_vec.end())
    {
        pr = {NULL, NULL, NULL};
        memcpy(pr.aes_key, decrypt_data, decrypt_data_size);
        memcpy(pr.mrenclave, mrenclave, mrenclave_size);
        client_info_vec.push_back(pr);
        // TRACE_ENCLAVE("Dispatch Info: local push back success");
    }
    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::aes_decrypt_client_messages(
    uint8_t *encrypt_aes_data,
    size_t encrypt_aes_data_size,
    uint8_t *mrenclave,
    size_t mrenclave_size,
    uint8_t **reply_data,
    size_t *reply_data_size,
    size_t client_id,
    size_t *reply_type)
{
    int ret = 1;
    uint8_t decrypt_data[1024];
    size_t decrypt_data_size;
    vector<client_info>::iterator it;
    string message;
    string re_message;
    vector<std::string> sp;
    size_t pos;

    uint8_t encrypt_data[1024];
    size_t encrypt_data_size;
    std::vector<uint8_t> marge_message_vec;

    for (it = client_info_vec.begin(); it != client_info_vec.end(); ++it)
    {
        // compare the mrencalve
        if (compare_key((*it).mrenclave, mrenclave, 32) == true)
        {
            ret = m_crypto->aes_decrypt(encrypt_aes_data, encrypt_aes_data_size, decrypt_data, &decrypt_data_size, (*it).aes_key);
            if (ret != 0)
            {
                TRACE_ENCLAVE("Dispatch Error: decrypty clients' requests failed.");
                ret = 1;
                return ret;
                ;
            }
            else
            {
                message = uint8_to_hex_string_version2(decrypt_data, decrypt_data_size);
                TRACE_ENCLAVE("Dispatch Info: Receiving message: %s", message.c_str());
            }
            break;
        }
    }
    if (it == client_info_vec.end())
    {
        TRACE_ENCLAVE("Dispatch Info: can not find local aes key");
        ret = 1;
        return ret;
        ;
    }

    // split the messag
    pos = message.find("#");
    if (pos != 0 || pos == string::npos)
    {
        TRACE_ENCLAVE("Can not find the start symbol #");
        ret = 1;
        return ret;
        ;
    }

    if (message[message.size() - 1] != '!')
    {
        TRACE_ENCLAVE("can not find the end symbol!");
        ret = 1;
        return ret;
        ;
    }
    message = message.substr(1, message.size() - 2);
    sp = split(message, "@");
    if (sp.size() < 1)
    {
        TRACE_ENCLAVE("split pki_certificate failed with size %ld", sp.size());
        ret = 1;
        return ret;
        ;
    }
    // test print
    TRACE_ENCLAVE("sp[0] %s", sp[0].c_str());
    TRACE_ENCLAVE("sp[1] %s", sp[1].c_str());
    if ((sp[0]).compare("state_init") == 0)
    {
        if (Init_system_state(it) != 0)
        {
            re_message = "#Init_Failure@" + sp[1] + "!";
        }
        else
        {
            re_message = "#Init_Success@" + sp[1] + "!";
        }
        *reply_type = 1;
    }
    else if ((sp[0]).compare("state_fetch") == 0)
    {
        // fetch client's latest state
        re_message = get_latest_client_state(it);
        re_message = "#Latest_State@" + sp[1] + "@" + re_message + "!";
        TRACE_ENCLAVE("Dispatch Info: state fetch messages.");
        *reply_type = 1;
    }
    else if ((sp[0]).compare("state_update") == 0)
    {
        TRACE_ENCLAVE("Dispatch Info: state update messages.");
        *reply_type = 0;
    }
    else
    {
        TRACE_ENCLAVE("Dispatch Error: unknown messages.");
    }

    // sendout messsges
    marge_message_vec = hex_string_to_uint8_vec_version2(re_message);
    ret = m_crypto->aes_encrypt(&marge_message_vec[0], marge_message_vec.size(), encrypt_data, &encrypt_data_size, (*it).aes_key);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Dispatcher Info: encrypt init state request failed.");
        ret = 1;
        return ret;
        ;
    }
    else
    {
        *reply_data = (uint8_t *)oe_host_malloc(encrypt_data_size);
        if (*reply_data == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            TRACE_ENCLAVE("Error: copying encrypt_ecdsa_data failed, out of memory");
            ret = 1;
            return ret;
            ;
        }
        memcpy(*reply_data, encrypt_data, encrypt_data_size);
        *reply_data_size = encrypt_data_size;
    }

    ret = 0;
exit:
    return ret;
}

/**
 * @brief init the client's state info
 * @return 0 success; 1 failure
 */
int ecall_dispatcher::Init_system_state(vector<client_info>::iterator it)
{
    int ret = 1;
    if ((*it).state_ptr == NULL)
    {
        TRACE_ENCLAVE("Dispatch Info: clients' state is initialized.");
        ((*it).state_ptr) = (state_info *)malloc(sizeof(state_info));
    }
    else
    {
        TRACE_ENCLAVE("Dispatch Error: system state has already been initialized.");
        ret = 1;
        return ret;
        ;
    }
    ret = 0;
exit:
    return ret;
}

/**
 * @brief init the client's state info
 * @return 0 success; 1 failure
 */
string ecall_dispatcher::get_latest_client_state(vector<client_info>::iterator it)
{
    string message;
    string state = uint8_to_hex_string((*it).state_ptr->hash, 32);
    return message = state + "@" + to_string((*it).state_ptr->index);
}

/*********************seal and unseal funtions *******************************/
/**
 * @brief seal_state_data
 * @param seal_policy
 * @param sealed_data
 * @param sealed_data_size
 * @return int
 */
int ecall_dispatcher::seal_state_data(
    int seal_policy,
    sealed_data_t **sealed_data,
    size_t *sealed_data_size)
{
    oe_result_t ret;
    uint8_t *blob;
    size_t blob_size;
    sealed_data_t *temp_sealed_data;
    unsigned char *data = NULL;
    unsigned char *optional_message = NULL;
    size_t data_size = 0;

    const char *state = "test plaintext";
    data = (unsigned char *)state;
    data_size = strlen((const char *)data) + 1;

    optional_message = (unsigned char *)state;
    size_t optional_message_size = strlen((const char *)data);

    const oe_seal_setting_t settings[] = {OE_SEAL_SET_POLICY(seal_policy)};
    ret = oe_seal(
        NULL,
        settings,
        sizeof(settings) / sizeof(*settings),
        data,
        data_size,
        optional_message,
        optional_message_size,
        &blob,
        &blob_size);
    if (ret != OE_OK)
    {
        TRACE_ENCLAVE("oe_seal() failed with %d\n", ret);
        return (int)ret;
    }
    if (blob_size > UINT32_MAX)
    {
        TRACE_ENCLAVE("blob_size is too large to fit into an unsigned int");
        ret = OE_OUT_OF_MEMORY;
        return (int)ret;
    }

    temp_sealed_data = (sealed_data_t *)oe_host_malloc(sizeof(*temp_sealed_data) + blob_size);
    if (temp_sealed_data == NULL)
    {
        ret = OE_OUT_OF_MEMORY;
        return (int)ret;
        ;
    }
    memset(temp_sealed_data, 0, sizeof(*temp_sealed_data));
    memcpy(temp_sealed_data->optional_message, optional_message, optional_message_size);
    temp_sealed_data->sealed_blob_size = blob_size;
    memcpy(temp_sealed_data + 1, blob, blob_size);
    *sealed_data = temp_sealed_data;
    *sealed_data_size = sizeof(*temp_sealed_data) + blob_size;
exit:
    oe_free(blob);
    return (int)ret;
}

/**
 * @brief compare two value equal
 * @param key1           // key  1
 * @param key2           // key  2
 * @param key_size
 * @return  Equal true   unequal false
 */
bool ecall_dispatcher::compare_key(
    uint8_t *key1,
    uint8_t *key2,
    size_t key_size)
{
    size_t index;
    bool ret = true;
    for (index = 0; index < key_size; index++)
    {
        if (key1[index] != key2[index])
        {
            ret = false;
            break;
        }
    }
    return ret;
}

void ecall_dispatcher::print_peers()
{
    // Re_runtime_tables.clear();
    vector<peer_info_t>::iterator it;
    for (it = peer_info_vec2.begin(); it != peer_info_vec2.end(); ++it)
    {
        TRACE_ENCLAVE("Index %zu: rsa_size: %zu, aes size: %zu, ecdsa size: %zu.", (*it).uuid, (*it).rsa_key_size, (*it).aes_key_size, (*it).ecdsa_key_size);
    }
    TRACE_ENCLAVE("Print Finish!");
}

// INFO ROTE I think just need to pass in uuid
int ecall_dispatcher::updateLocalASECounterTable(size_t AE_uuid, uint8_t *ITHash, size_t ITHash_size)
{
    int ret = 1;
    std::vector<Ae_queues> *batch_queue;
    batch_queue = (std::vector<Ae_queues> *)malloc(ITHash_size + 10);
    memset(batch_queue, 0, ITHash_size + 10);
    memcpy(batch_queue, ITHash, ITHash_size);
    for (size_t i = 0; i < batch_queue->size(); i++)
    {
        vector<Local_AE_counter_table>::iterator it;
        it = std::find(Re_persistent_state_table.local_aes.begin(), Re_persistent_state_table.local_aes.end(), batch_queue->at(i).uuid);
        if (it == Re_persistent_state_table.local_aes.end())
        {
            TRACE_ENCLAVE("Please check attestation part!iter->uuid %ld and size is %ld", batch_queue->at(i).uuid, batch_queue->size());
        }
        else
        {
            uint8_t *decrypt_data;
            size_t decrypt_data_size = 0;
            decrypt_data = (uint8_t *)malloc(batch_queue->at(i).encrypt_data_size + 128);
            memset(decrypt_data, 0, batch_queue->at(i).encrypt_data_size + 128);

            ret = m_crypto->aes_decrypt(batch_queue->at(i).encrypt_data, batch_queue->at(i).encrypt_data_size, decrypt_data, &decrypt_data_size, it->m_aes_key);
            if (ret != 0)
            {
                TRACE_ENCLAVE("verify ase decrypt failed!And your decrypt_data_size is %zu", decrypt_data_size);
                return 1;
            }
            Ae_queues_decrypt tmpera;
            memcpy(tmpera.ITHash, decrypt_data, 32);
            tmpera.uuid = batch_queue->at(i).uuid;
            batch_queue_decrypt.push_back(tmpera);
            oe_free(decrypt_data);
            decrypt_data = NULL;
            decrypt_data_size = 0;
        }
    }
    oe_free(batch_queue);
    batch_queue = NULL;
    uint8_t *temp_buffer;
    uint8_t tempHash[32];
    size_t temp_size = batch_queue_decrypt.size() * sizeof(Ae_queues_decrypt);
    temp_buffer = (uint8_t *)malloc(temp_size + 10);
    memset(temp_buffer, 0, temp_size + 10);
    memcpy(temp_buffer, &batch_queue_decrypt, temp_size);
    batch_queue_decrypt.clear();
    ret = m_crypto->Sha256(temp_buffer, temp_size, tempHash);
    oe_free(temp_buffer);
    temp_buffer = NULL;
    if (ret != 0)
    {
        TRACE_ENCLAVE("Sha256 failed");
        return 1;
    }
    memcpy(Re_persistent_state_table.ITHash, tempHash, 32);
    // INFO POLICY_UNIQUE is 1 and POLICY_PRODUCT is 2
    ret = acceptNewState(1); // Seal the last status
    if (ret != 0)
    {
        TRACE_ENCLAVE("acceptNewState failed.!!!Seal failed!!");
        ret = 1;
        return ret;
    }
    ret = 0;
    return ret;

}; // INFO ROTE

/**
 * @brief INFO ROTE; On the basis of policy to signed message
 * 0 is first ECHO
 * 1 is returned ECHO
 * 2 is final ACK
 * default signed MC
 * @param AE_uuid
 * @param policy
 * @param signed_data
 * @param signed_data_size
 * @param encrypt_data
 * @param encrypt_data_size
 * @return int 0 success 1 failed
 */
int ecall_dispatcher::ecdsa_signed(size_t uuid,
                                   int policy,
                                   unsigned char **signed_data,
                                   size_t *signed_data_size,
                                   unsigned char **encrypt_data,
                                   size_t *encrypt_data_size)
{
    int ret = 1;
    string message = "";
    uint8_t sig_message[64];
    string tmp;
    size_t sig_size;
    uint8_t *encrypt_buffer;
    size_t encrypt_buffer_size = 0;
    vector<peer_info_t>::iterator it;
    vector<Local_AE_counter_table>::iterator it_local;
    // check whether the RE
    it = std::find(peer_info_vec2.begin(), peer_info_vec2.end(), uuid);
    if (it == peer_info_vec2.end())
    {
        // Can not find the RE
        for (size_t i = 0; i < peer_info_vec2.size(); i++)
        {
            TRACE_ENCLAVE("UUID peer is %d", peer_info_vec2[i].uuid);
        }
        TRACE_ENCLAVE("Can not find RE!!Please check attestation part! %zu", uuid);
        ret = 1;
        return ret;
    }
    // 0 is first ECHO
    // 1 is returned ECHO
    // 2 is final ACK
    // default signed MC

    message = std::to_string(nonce);
    switch (policy)
    {
    case 0:
        // Echo2
        break;
    case 1:
        if (Re_persistent_state_table.quorum == peer_info_vec2.size())
        {
            memcpy(sig_message, message.c_str(), 64);
            Re_persistent_state_table.quorum = 0;
        }
        break;
    case 2:
        // Final
        break;
    default:
        // signed MC
        // split join nonce and
        // message = std::to_string((*it_local).nonce);
        if (message.size() + 32 > 64)
        {
            TRACE_ENCLAVE("Your message is bigger !! Now your size is %zu", message.size() + 32);
            ret = 1;
            return ret;
            ;
        }
        memcpy(sig_message, Re_persistent_state_table.ITHash, 32);
        ret = 0;

        break;
    }
    encrypt_buffer = (uint8_t *)malloc(sizeof(sig_message) + 150); // TODO 如何计算encrypt buffer的大小
    ret = m_crypto->aes_encrypt(sig_message, sizeof(sig_message), encrypt_buffer, &encrypt_buffer_size, Re_persistent_state_table.m_aes_key);
    *encrypt_data = (uint8_t *)oe_host_malloc(encrypt_buffer_size);
    memcpy(*encrypt_data, encrypt_buffer, encrypt_buffer_size);
    *encrypt_data_size = encrypt_buffer_size;
    free(encrypt_buffer);
    encrypt_buffer = NULL;
    ret = 0;
    return ret;
};

int ecall_dispatcher::verify(
    // INFO ROTE
    size_t RE_uuid,
    int policy,
    unsigned char *sig_data,
    size_t sig_data_size,
    unsigned char *encrypt_data,
    size_t encrypt_data_size)
{
    // TODO 加一个status
    int ret = 1;
    uint8_t *decrypt_data;
    size_t decrypt_data_size = 0;
    uint8_t ITHash[32];
    vector<peer_info_t>::iterator it;
    vector<string> sp;
    string string_message;
    int nonce;
    int other_counter;
    // check whether the AE uuid
    it = std::find(peer_info_vec2.begin(), peer_info_vec2.end(), RE_uuid);
    if (it == peer_info_vec2.end())
    {
        // Can not find the AE
        TRACE_ENCLAVE("Can not find RE to verify!!Please check attestation part!%d", RE_uuid);
        ret = 1;
        return ret;
        ;
    }

    // 0 is first ECHO
    // 1 is returned ECHO
    // 2 is final ACK
    // default signed MC
    decrypt_data = (uint8_t *)malloc(encrypt_data_size + 128);
    memset(decrypt_data, 0, encrypt_data_size + 128);
    ret = m_crypto->aes_decrypt(encrypt_data, encrypt_data_size, decrypt_data, &decrypt_data_size, (*it).aes_key);
    if (ret != 0)
    {
        TRACE_ENCLAVE("verify ase decrypt failed!");
        ret = 1;
        return ret;
        ;
    }
    ret = 1;
    Re_persistent_state_table.quorum++; // If verify success add a quorum;
    switch (policy)
    {
    case 0:
        break;
    case 1:
        break;
    case 2:
        break;
    default:
        memcpy(Re_persistent_state_table.ITHash, decrypt_data, 32); // IThash
        memcpy((*it).ITHash, ITHash, 32);
        break;
    }
    ret = 0;
exit:
    return ret;
}

/**
 * @brief Accept a new state that create a seal、write seal data into disk
 *
 * @param sealPolicy
 * @param sealed_data
 * @param sig_data_size
 * @return int
 */
int ecall_dispatcher::acceptNewState(int sealPolicy)
{
    int ret = 1;
    oe_result_t result;
    uint8_t *blob;
    size_t blob_size;
    unsigned char *Ocall_buffer;
    unsigned char *data;
    size_t optional_message_size;
    const oe_seal_setting_t settings[] = {OE_SEAL_SET_POLICY(sealPolicy)};
    uint8_t ITHash[32]; // Hash
    data = (unsigned char *)malloc(sizeof(Re_persistent_state_table) + 1);
    unsigned char *optional_message = NULL;
    size_t data_size = 0;

    const char *state = "test plaintext";
    memcpy(data, &Re_persistent_state_table, sizeof(Re_persistent_state_table));
    data_size = sizeof(Re_persistent_state_table) + 1;

    ret = m_crypto->Sha256(data, data_size, ITHash);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Sha256 Hash failed");
        ret = 1;
        return ret;
        ;
    }
    optional_message = (unsigned char *)state;
    optional_message_size = strlen((const char *)state);
    result = oe_seal(
        NULL,
        settings,
        sizeof(settings) / sizeof(*settings),
        data,
        data_size,
        optional_message,
        optional_message_size,
        &blob,
        &blob_size);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("oe_seal() failed with %d\n", ret);
        ret = 1;
        return ret;
        ;
    }
    if (blob_size > UINT32_MAX)
    {
        TRACE_ENCLAVE("blob_size is too large to fit into an unsigned int");
        ret = 1;
        ret = 1;
        return ret;
        ;
    }
    // TRACE_ENCLAVE("oe_seal() successful with %d\n", blob_size);
    Ocall_buffer = (unsigned char *)oe_host_malloc(blob_size + 1);
    memcpy(Ocall_buffer, blob, blob_size);
    result = seal_host_write(&ret, blob_size + 1, Ocall_buffer);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("Ocall save file is failed.");
        ret = 1;
        return ret;
        ;
    }
    // after seal and update ITHash
    memcpy(Re_persistent_state_table.ITHash, ITHash, 32);
    ret = 0;
exit:
    oe_free(data);
    data = NULL;
    oe_free(blob);
    blob = NULL;
    oe_host_free(Ocall_buffer);
    Ocall_buffer = NULL;
    return ret;
}

int ecall_dispatcher::verify_ed25519(uint8_t *signture, size_t signture_size, uint8_t *source_text, size_t source_text_size)
{
    int ret = 1;
    ret = m_crypto->Ed25519(source_text, source_text_size, signture);
    if (ret == 0)
    {
        TRACE_ENCLAVE("verify_ed25519 successful!");
    }
    return ret;
}

int ecall_dispatcher::signed_with_verify(size_t uuid,
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
    int ret = 1;
    // TODO 加一个status
    uint8_t decrypt_data[1024];
    size_t decrypt_data_size;
    vector<peer_info_t>::iterator it;
    vector<string> sp;
    string string_message;
    int nonce;
    int other_counter;

    string message = "";
    uint8_t sig_message[64] = {0};
    // uint8_t *sig;
    size_t sig_size;
    // uint8_t *encrypt_buffer;
    uint8_t encrypt_buffer[1024];
    size_t encrypt_buffer_size;
    vector<Local_AE_counter_table>::iterator it_local;

    // check whether the RE uuid
    it = std::find(peer_info_vec2.begin(), peer_info_vec2.end(), uuid);
    if (it == peer_info_vec2.end())
    {
        // Can not find the RE
        TRACE_ENCLAVE("Can not find RE to verify!!Please check attestation part!%d", uuid);
        ret = 1;
        return ret;
        ;
    }

    // 0 is first ECHO
    // 1 is returned ECHO
    // 2 is final ACK
    // default signed MC
    memset(decrypt_data, 0, sizeof(decrypt_data));
    ret = m_crypto->aes_decrypt(encrypt_data, encrypt_data_size, decrypt_data, &decrypt_data_size, (*it).aes_key);
    if (ret != 0)
    {
        TRACE_ENCLAVE("verify ase decrypt failed!");
        ret = 1;
        return ret;
        ;
    }
    ret = 1;

    // string_message = (char*)decrypt_data;// conver uint8_t into string
    Re_persistent_state_table.quorum++; // If verify success add a quorum;
    switch (policy)
    {
    case 0:
        break;
    case 1:
        break;
    case 2:
        break;
    default:
        memcpy(Re_persistent_state_table.ITHash, decrypt_data, 32); // verify successful save ithash
        // TRACE_ENCLAVE("decrypt_data_size IS %zu", decrypt_data_size);
        break;
    }
    ret = 0;
    // SIGN Something
    message = std::to_string((*it).nonce); // TODO
    switch (signed_policy)
    {
    case 0:
        // Echo2
        // message = "return echo2@" + std::to_string((*it).nonce);
        memset(sig_message, 0, sizeof(sig_message));
        memcpy(sig_message, message.c_str(), message.size());
        break;
    case 1:
        if (Re_persistent_state_table.quorum == peer_info_vec2.size())
        {
            memset(sig_message, 0, sizeof(sig_message));
            memcpy(sig_message, message.c_str(), message.size());
        }
        break;
    case 2:
        // Final
        memset(sig_message, 0, sizeof(sig_message));
        memcpy(sig_message, message.c_str(), message.size());
        break;
    default:
        break;
    }
    ret = m_crypto->aes_encrypt(sig_message, sizeof(sig_message), encrypt_buffer, &encrypt_buffer_size, Re_persistent_state_table.m_aes_key);
    *encrypt_data_out = (uint8_t *)oe_host_malloc(encrypt_buffer_size + 1);
    memcpy(*encrypt_data_out, encrypt_buffer, encrypt_buffer_size);
    *encrypt_data_out_size = encrypt_buffer_size;
    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::LedgerRead_key(uint8_t **publickey_id, size_t *publickey_id_size, uint8_t **sgx_uid, size_t *sgx_uid_size)
{
    int ret = 1;
    *sgx_uid = (uint8_t *)oe_host_malloc(sizeof(m_enclave_signer_id) + 1);
    if (*sgx_uid == nullptr)
    {
        TRACE_ENCLAVE("sgx_uid malloc failed!!!");
        return ret;
    }
    memset(*sgx_uid, 0, sizeof(m_enclave_signer_id) + 1);
    memcpy(*sgx_uid, m_enclave_signer_id, sizeof(m_enclave_signer_id));
    *sgx_uid_size = sizeof(m_enclave_signer_id);

    uint8_t m_rsa_public_key[512];
    m_crypto->copy_rsa_public_key(m_rsa_public_key);
    *publickey_id = (uint8_t *)oe_host_malloc(512);
    if (*publickey_id == nullptr)
    {
        TRACE_ENCLAVE("publickey_id malloc failed!!!");
        return ret;
    }

    memset(*publickey_id, 0, 512);
    memcpy(*publickey_id, m_rsa_public_key, 512);
    *publickey_id_size = 512;
    ret = 0;
    TRACE_ENCLAVE("LedgerRead Successful!");
    return ret;
}

int ecall_dispatcher::LedgerRead_other_key(uint8_t **publickey_id, size_t *publickey_id_size, uint8_t **sgx_uid, size_t *sgx_uid_size, size_t uuid)
{
    int ret = 1;
    *sgx_uid = (uint8_t *)oe_host_malloc(sizeof(m_enclave_signer_id) + 1);
    if (*sgx_uid == nullptr)
    {
        TRACE_ENCLAVE("sgx_uid malloc failed!!!");
        return ret;
    }
    memset(*sgx_uid, 0, sizeof(m_enclave_signer_id) + 1);
    memcpy(*sgx_uid, m_enclave_signer_id, sizeof(m_enclave_signer_id));
    *sgx_uid_size = sizeof(m_enclave_signer_id);

    *publickey_id = (uint8_t *)oe_host_malloc(512);
    if (*publickey_id == nullptr)
    {
        TRACE_ENCLAVE("publickey_id malloc failed!!!");
        return ret;
    }
    memset(*publickey_id, 0, 512);
    vector<peer_info_t>::iterator it;
    it = std::find(peer_info_vec2.begin(), peer_info_vec2.end(), uuid);
    if (it != peer_info_vec2.end())
    {
        memcpy(*publickey_id, (*it).rsa_public_key, 512);
        *publickey_id_size = 512;

        ret = 0;
        TRACE_ENCLAVE("LedgerOtherRead Successful!");
        return ret;
    }
    else
    {
        TRACE_ENCLAVE("LedgerOtherRead failed! Can not find the peer message. Now uuid is %d", uuid);
        return 1;
    }
}
