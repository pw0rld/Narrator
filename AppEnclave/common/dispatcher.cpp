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
#include <openenclave/attestation/attester.h>
#include <openenclave/attestation/sgx/report.h>
#include <openenclave/attestation/verifier.h>
#include <openenclave/enclave.h>
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
    vector<string> res;
    if ("" == str)
        return res;
    // covert string to char array
    char *strs = new char[str.length() + 1];
    strcpy(strs, str.c_str());

    char *d = new char[delim.length() + 1];
    strcpy(d, delim.c_str());

    char *p = strtok(strs, d);
    while (p)
    {
        string s = p;
        res.push_back(s);
        p = strtok(NULL, d);
    }
    return res;
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
    // TRACE_ENCLAVE("Crypto Init %d.", m_initialized);
}

ecall_dispatcher::~ecall_dispatcher()
{
    if (m_crypto)
        delete m_crypto;

    if (m_attestation)
        delete m_attestation;
}

bool ecall_dispatcher::initialize(const char *name)
{
    bool ret = false;
    uint8_t *report;
    size_t report_size = 0;
    size_t other_enclave_signer_id_size = 0;
    oe_result_t result = OE_OK;
    oe_report_t parsed_report = {0};
    m_name = name;
    m_crypto = new Crypto();
    if (m_crypto == nullptr)
    {
        TRACE_ENCLAVE("Error: cannot create crypto.");
        goto exit;
    }

    other_enclave_signer_id_size = sizeof(m_other_enclave_signer_id);
    result = oe_get_report_v2(0, NULL, 0, NULL, 0, &report, &report_size); // obtain my mrenclave
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("Error: oe_get_report_v2 failed.(%s)", oe_result_str(result));
        ret = 1;
        goto exit;
    }

    result = oe_parse_report(report, report_size, &parsed_report);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("Error: oe_get_evidence failed.(%s)", oe_result_str(result));
        ret = 1;
        goto exit;
    }
    memcpy(m_other_enclave_signer_id, parsed_report.identity.unique_id, 32);
    m_attestation = new Attestation(m_crypto, m_other_enclave_signer_id);
    if (m_attestation == nullptr)
    {

        goto exit;
    }
    ret = 0;
exit:
    return ret;
}

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
        goto exit;
    }

    if (m_attestation->get_format_settings(
            format_id, &format_settings, &format_settings_size) == false)
    {
        TRACE_ENCLAVE("Error: get_enclave_format_settings failed");
        goto exit;
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
            goto exit;
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

    // Generate a format settings so that the enclave that receives this format
    // settings can attest this enclave.
    if (PRINT_DISPATCH_MESSAGES)
    {
        TRACE_ENCLAVE("Dispatcher Info: get_enclave_format_settings");
    }
    ret = 0;
exit:
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

    // uint8_t ecdsa_public_key[65];
    uint8_t m_rsa_public_key[512];
    uint8_t *evidence = nullptr;
    size_t evidence_size = 0;
    uint8_t *key_buffer = nullptr;
    int ret = 1;

    if (PRINT_DISPATCH_MESSAGES)
    {
        TRACE_ENCLAVE("Dispatcher Info: get_evidence_with_public_key");
    }

    if (m_initialized != 0)
    {
        TRACE_ENCLAVE("Error: ecall_dispatcher initialization failed.");
        goto exit;
    }

    m_crypto->copy_rsa_public_key(m_rsa_public_key);
    // Generate evidence for the public key so that the enclave that
    // receives the key can attest this enclave.
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
        goto exit;
    }

    // Allocate memory on the host and copy the evidence over.
    // enclave can directly write into host memory
    *evidence_buffer = (uint8_t *)oe_host_malloc(evidence_size);
    if (*evidence_buffer == nullptr)
    {
        ret = OE_OUT_OF_MEMORY;
        TRACE_ENCLAVE("Error: copying evidence_buffer failed, out of memory");
        goto exit;
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
        goto exit;
    }
    // m_crypto->copy_rsa_public_key(key_buffer);
    memcpy(key_buffer, m_rsa_public_key, sizeof(m_rsa_public_key));
    *pem_key = key_buffer;
    *pem_key_size = sizeof(m_rsa_public_key);

    ret = 0;
    if (PRINT_DISPATCH_MESSAGES)
    {
        TRACE_ENCLAVE("Dispatcher Info: get_evidence_with_public_key succeeded");
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
    uint8_t encrypt_data[1024];
    size_t encrypt_data_size;

    if (m_initialized != 0)
    {
        TRACE_ENCLAVE("Error: ecall_dispatcher initialization failed.");
        goto exit;
    }

    // Attest the evidence and accompanying key.
    if (m_attestation->attest_attestation_evidence(format_id, evidence, evidence_size, pem_key, pem_key_size) == false)
    {
        TRACE_ENCLAVE("Error: verify_evidence_and_set_public_key failed.");
        goto exit;
    }
    m_crypto->copy_other_rsa_key(pem_key, pem_key_size);

    if (PRINT_DISPATCH_MESSAGES)
    {
        TRACE_ENCLAVE("Dispatcher Info: verify_evidence_and_set_public_key succeeded.");
    }
    ret = 0;

exit:
    return ret;
}

/**
 * @brief compare two componets
 * @param rsa_public_key1
 * @param rsa_public_key2
 * @param rsa_public_key_size
 * @return  Equal true   unequal false
 */
bool ecall_dispatcher::compare_rsa_key(
    uint8_t *rsa_public_key1,
    uint8_t *rsa_public_key2,
    size_t rsa_public_key_size)
{
    size_t index;
    bool ret = true;
    for (index = 0; index < rsa_public_key_size; index++)
    {
        if (rsa_public_key1[index] != rsa_public_key2[index])
        {
            ret = false;
            break;
        }
    }
    return ret;
}

/** use rsa key to encrypt aes key
 * @brief
 * @param sig_aes_data
 * @param sig_aes_data_size
 * @return int
 */
int ecall_dispatcher::rsa_encrypt_aes_key(
    uint8_t **encrypt_aes_data,
    size_t *encrypt_aes_data_size,
    uint8_t **mrenclave,
    size_t *mrenclave_size)
{
    int ret = 1;
    uint8_t encrypt_data[1024];
    size_t encrypt_data_size;
    uint8_t m_aes_key[Aes_Key_Size];
    uint8_t other_rsa_public_key[512];
    m_crypto->get_aes_key(m_aes_key);
    m_crypto->retrieve_othet_rsa_public_key(other_rsa_public_key);

    // use the receiver rsa public key to encrypt the aes secret key
    ret = m_crypto->rsa_encrypt(other_rsa_public_key, sizeof(other_rsa_public_key), m_aes_key, sizeof(m_aes_key), encrypt_data, &encrypt_data_size);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Dispatcher Info: encrypt aes key failed.");
        goto exit;
    }
    else
    {
        *encrypt_aes_data = (uint8_t *)oe_host_malloc(encrypt_data_size);
        if (*encrypt_aes_data == nullptr)
        {
            ret = OE_OUT_OF_MEMORY;
            TRACE_ENCLAVE("Error: copying encrypt_ecdsa_data failed, out of memory");
            goto exit;
        }
        memcpy(*encrypt_aes_data, encrypt_data, encrypt_data_size);
        *encrypt_aes_data_size = encrypt_data_size;
    }

    // output the mrenclave
    *mrenclave = (uint8_t *)oe_host_malloc(sizeof(m_other_enclave_signer_id));
    memcpy(*mrenclave, m_other_enclave_signer_id, sizeof(m_other_enclave_signer_id));
    *mrenclave_size = sizeof(m_other_enclave_signer_id);
    if (PRINT_DISPATCH_MESSAGES)
    {
        // TRACE_ENCLAVE("Dispatcher Info: mrenclave succed.");
    }
    ret = 0;
exit:
    return ret;
}

string rand_str(int len)
{
    string str;
    char c;
    string end_synbol = "@";
    int idx;
    for (int i = 0; i < len; i++)
    {
        c = 'a' + rand() % 26;
        str.push_back(c);
    }
    str += end_synbol; // The end symbol
    return str;
}

/**
 * @brief sent init application state request
 * @param encrypt_data
 * @param encrypt_data_size
 * @return int
 */
int ecall_dispatcher::aes_encrypt_client_messages(
    uint8_t *requests_message,
    size_t requests_message_size,
    uint8_t **encrypt_data,
    size_t *encrypt_data_size,
    uint8_t **mrenclave,
    size_t *mrenclave_size)
{

    int ret = 1;
    uint8_t encrypt_aes_data[1024];
    size_t encrypt_aes_data_size;
    uint8_t data[1024000];
    uint8_t m_aes_key[Aes_Key_Size];
    uint8_t ITHash[32];
    memset(data, 0, sizeof(data));
    memset(encrypt_aes_data, 0, sizeof(encrypt_aes_data));
    memset(m_aes_key, 0, sizeof(m_aes_key));
    memset(ITHash, 0, sizeof(ITHash));
    m_crypto->get_aes_key(m_aes_key);
    string message = rand_str(1000000); // 1000 K
    // TRACE_ENCLAVE("message size is %d",message.size());
    if ((requests_message_size + message.size()) > sizeof(data))
    {
        TRACE_ENCLAVE("Encrypt data buffer is more small!!");
        goto exit;
    }
    memcpy(data, requests_message, requests_message_size);
    memcpy(data + requests_message_size, message.c_str(), message.size());
    // message.shrink_to_fit(); //free the string
    // Hash setp
    ret = m_crypto->Sha256(data, sizeof(data), ITHash);
    if (ret != 0)
    {
        TRACE_ENCLAVE("AE Hash worrying!");
        goto exit;
    }
    // store and seal
    ret = seal_state_data_host(requests_message, requests_message_size, message, ITHash);
    if (ret != 0)
    {
        TRACE_ENCLAVE("seal_state_data_host worrying!");
        goto exit;
    }
    // cout <<"Debug 1" << endl;
    ret = m_crypto->aes_encrypt(ITHash, sizeof(ITHash), encrypt_aes_data, &encrypt_aes_data_size, m_aes_key);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Dispatcher Info: encrypt init state request failed.");
        goto exit;
    }

    *encrypt_data = (uint8_t *)oe_host_malloc(encrypt_aes_data_size);
    if (*encrypt_data == nullptr)
    {
        ret = 1;
        TRACE_ENCLAVE("Error: copying encrypt_ecdsa_data failed, out of memory");
        goto exit;
    }
    memcpy(*encrypt_data, encrypt_aes_data, encrypt_aes_data_size);
    *encrypt_data_size = encrypt_aes_data_size;

    // output the mrenclave
    *mrenclave = (uint8_t *)oe_host_malloc(sizeof(m_other_enclave_signer_id));
    if (*mrenclave == nullptr)
    {
        ret = 1;
        TRACE_ENCLAVE("Error: copying encrypt_ecdsa_data failed, out of memory");
        goto exit;
    }
    memcpy(*mrenclave, m_other_enclave_signer_id, sizeof(m_other_enclave_signer_id));
    *mrenclave_size = sizeof(m_other_enclave_signer_id);
    ret = 0;
    // TRACE_ENCLAVE("aes_encrypt_client_messages successful!Size is %d",encrypt_aes_data_size);
    // for(size_t i = 0 ; i< encrypt_aes_data_size;i++){
    //     TRACE_ENCLAVE("The encrypt data is 0x%x",encrypt_aes_data[i]);
    // }
exit:
    return ret;
}

/**
 * @brief process SE's messages
 * @param reply_data
 * @param reply_data_size
 * @return int
 */
int ecall_dispatcher::aes_decrypt_server_messages(
    uint8_t *reply_data,
    size_t reply_data_size,
    size_t *is_ready)
{
    int ret = 1;
    string message;
    uint8_t decrypt_data[1024];
    size_t decrypt_data_size;
    uint8_t m_aes_key[Aes_Key_Size];
    m_crypto->get_aes_key(m_aes_key);
    vector<std::string> sp;
    size_t pos;

    ret = m_crypto->aes_decrypt(reply_data, reply_data_size, decrypt_data, &decrypt_data_size, m_aes_key);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Dispatch Error: decrypty servers' requests failed.");
        goto exit;
    }
    // TRACE_ENCLAVE("Request Size:%ld. ", decrypt_data_size);
    message = uint8_to_hex_string_version2(decrypt_data, decrypt_data_size);
    // Test print
    TRACE_ENCLAVE("Dispatch Info: Receiving message: %s", message.c_str());
    // split the messag
    pos = message.find("#");
    if (pos != 0 || pos == string::npos)
    {
        TRACE_ENCLAVE("Can not find the start symbol #");
        goto exit;
    }
    if (message[message.size() - 1] != '!')
    {
        TRACE_ENCLAVE("can not find the end symbol!");
        goto exit;
    }
    message = message.substr(1, message.size() - 2);
    sp = split(message, "@");
    if (sp.size() < 1)
    {
        TRACE_ENCLAVE("split pki_certificate failed with size %ld", sp.size());
        goto exit;
    }
    // test print
    // TRACE_ENCLAVE("sp[0] %s", sp[0].c_str());
    // TRACE_ENCLAVE("sp[1] %s", sp[1].c_str());

    if ((sp[0]).compare("Init_Success") == 0)
    {
        // verify the nonce in reply
        // set_system_ready();
        *is_ready = 1;
    }
    else if ((sp[0]).compare("Init_Failure") == 0)
    {
        *is_ready = 0;
    }
    else if ((sp[0]).compare("Latest_State") == 0)
    {
        // TODO: compare the state with sealed state
        *is_ready = 1;
    }
    else
    {
        TRACE_ENCLAVE("Dispatch Error: unknown messages.");
    }
    ret = 0;
exit:
    return ret;
}

/**
 * @brief unseal data
 * @param sealed_data
 * @param sealed_data_size
 * @param data
 * @param data_size
 * @return int
 */
// TODO
int ecall_dispatcher::unseal_state_data(
    const sealed_data_t *sealed_data,
    size_t sealed_data_size,
    unsigned char **data,
    size_t *data_size)
{
    uint8_t *temp_data;
    if (sealed_data_size != sealed_data->sealed_blob_size + sizeof(*sealed_data))
    {
        TRACE_ENCLAVE("Seal data does not match the seal data size. Expected %zd, got: "
                      "%zd",
                      sealed_data->sealed_blob_size + sizeof(*sealed_data),
                      sealed_data_size);
        return ERROR_INVALID_PARAMETER;
    }

    int ret = (int)oe_unseal(
        (const uint8_t *)(sealed_data + 1),
        sealed_data->sealed_blob_size,
        sealed_data->optional_message,
        strlen((char *)sealed_data->optional_message),
        &temp_data,
        data_size);
    std::string status_string(temp_data, temp_data + *data_size);
    if (ret != OE_OK)
    {
        TRACE_ENCLAVE("oe_unseal() returns %d\n", ret);
        goto exit;
    }

    *data = (unsigned char *)oe_host_malloc(*data_size);
    if (*data == NULL)
    {
        ret = OE_OUT_OF_MEMORY;
        goto exit;
    }
    memcpy(*data, temp_data, *data_size);

exit:
    oe_free(temp_data);
    return ret;
}

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

    // TODO: prepare the sealed application state
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
        goto exit;
    }
    if (blob_size > UINT32_MAX)
    {
        TRACE_ENCLAVE("blob_size is too large to fit into an unsigned int");
        ret = OE_OUT_OF_MEMORY;
        goto exit;
    }

    temp_sealed_data = (sealed_data_t *)oe_host_malloc(sizeof(*temp_sealed_data) + blob_size);
    if (temp_sealed_data == NULL)
    {
        ret = OE_OUT_OF_MEMORY;
        goto exit;
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

int ecall_dispatcher::seal_state_data_host(
    uint8_t *requests_message,
    size_t requests_message_size,
    string status_message,
    uint8_t *ITHash)
{

    int seal_policy = 1; // policy for seal
    int ret = 1;
    uint8_t *blob;
    size_t blob_size;
    oe_result_t result;
    state_info_t state_info_table;
    unsigned char *Ocall_buffer;
    unsigned char *data = NULL;
    unsigned char *optional_message = NULL;
    size_t data_size = 0;
    size_t optional_message_size;
    const char *state = "test plaintext";
    const oe_seal_setting_t settings[] = {OE_SEAL_SET_POLICY(seal_policy)};
    // state_info_table.state_size = status_message.size();
    // state_info_table.requests_I_size = requests_message_size;
    // if ((requests_message_size > sizeof(state_info_table.requests_I)) || (status_message.size() > sizeof(state_info_table.state)))
    // {
    //     TRACE_ENCLAVE("Size is more bigger than table.You size is %d and %d", requests_message_size, status_message.size());
    //     goto exit;
    // }
    memcpy(state_info_table.ITHash, ITHash, 32);
    memcpy(state_info_table.requests_I, requests_message, requests_message_size);
    memcpy(state_info_table.state, status_message.c_str(), status_message.size());
    // TRACE_ENCLAVE("State size is %d and status size is %d requests message size %d",sizeof(state_info_table) + 1,status_message.size(),requests_message_size);
    data = (unsigned char *)malloc(sizeof(state_info_table) + 1);
    if (data == nullptr)
    {
        TRACE_ENCLAVE("malloc a buffer failed!!");
        goto exit;
    }
    memcpy(data, &state_info_table, sizeof(state_info_table));
    data_size = sizeof(state_info_table) + 1;

    optional_message = (unsigned char *)state;
    optional_message_size = strlen((const char *)data);

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
        goto exit;
    }
    if (blob_size > UINT32_MAX)
    {
        TRACE_ENCLAVE("blob_size is too large to fit into an unsigned int");
        ret = 1;
        goto exit;
    }
    // OCall
    Ocall_buffer = (unsigned char *)oe_host_malloc(blob_size + 1);
    memcpy(Ocall_buffer, blob, blob_size);
    result = seal_host_write(&ret, blob_size + 1, Ocall_buffer);
    if (result != OE_OK)
    {
        TRACE_ENCLAVE("Ocall save file is failed.");
        goto exit;
    }
    // TRACE_ENCLAVE("Successful seal store state!!");
    ret = 0;
exit:
    // TODO Free something
    // oe_free(optional_message);
    optional_message = NULL;
    oe_free(blob);
    oe_host_free(Ocall_buffer); // This buffer is in host
    blob = NULL;
    Ocall_buffer= NULL;
    oe_free(data);
    data = NULL;
    return ret;
}