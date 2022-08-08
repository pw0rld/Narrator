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
#include "message_requests.h"
#include "misc.h"
// include <boost/uuid/uuid.hpp>
//#include <boost/uuid/uuid_io.hpp>
//#include <boost/uuid/uuid_generators.hpp>

extern string my_ip;
extern uint32_t my_port;
extern string my_role;
extern tcp_server *ser;

// SGX Local Attestation UUID.
static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
using namespace std;

// transform uint8 to string
std::string uint8_to_hex_string(const uint8_t *v, const size_t size)
{
    std::stringstream output;
    output << std::hex << std::setfill('0');
    for (int i = 0; i < size; i++)
    {
        output << std::hex << std::setw(2) << static_cast<int>(v[i]);
    }
    return output.str();
}

// transform string to uint8, and save in vector
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

std::vector<uint8_t> hex_string_to_uint8_vec_version2(const string &hex)
{
    std::vector<uint8_t> bytes;
    for (unsigned int i = 0; i < hex.length(); i += 1)
    {
        int tmp = hex[i] - 0; // covert to acsii
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

/**********************Local Attestation*********************************/
// verifier creates local attestation format_setting
string create_attestation_local_format_setting(oe_enclave_t *attester_enclaves)
{
    uint8_t *format_settings;
    size_t format_settings_size;
    oe_uuid_t *format_id = &sgx_local_uuid;
    oe_result_t result = OE_OK;
    int ret;
    result = get_enclave_format_settings(
        attester_enclaves,
        &ret,
        format_id,
        &format_settings,
        &format_settings_size);
    if ((result != OE_OK) || (ret != 0))
        cout << "[-]Local Re create local attestation format setting failed. Peer" << my_ip << to_string(my_port) << ": failed to generate format_settings for local attestation ." << oe_result_str(result) << endl;
    string format_settings_message = "#local_format_setting," + my_ip + "," + to_string(my_port) + "," + uint8_to_hex_string(format_settings, format_settings_size) + ",";
    free(format_settings);
    format_settings = NULL;
    free(format_id);
    format_id = NULL;
    return format_settings_message;
}

// obtain verifier's format_setting and generate local attestation evidence
string create_local_attestation_evidence(oe_enclave_t *attester_enclaves, vector<std::string> sp)
{
    int ret;
    uint8_t *evidence;
    size_t evidence_size;
    uint8_t *pem_key;
    size_t pem_key_size;
    uint8_t *format_settings;
    size_t format_settings_size;
    oe_uuid_t *format_id = &sgx_local_uuid;
    oe_result_t result = OE_OK;

    // sp[0] message type; sp[1]: ip; sp[2]: port; sp[3] format_settings
    std::vector<uint8_t> format_settings_vec = hex_string_to_uint8_vec(sp[3]);
    format_settings = &format_settings_vec[0];
    format_settings_size = format_settings_vec.size();
    result = get_evidence_with_public_key(
        attester_enclaves,
        &ret,
        format_id,
        format_settings,
        format_settings_size,
        &pem_key,
        &pem_key_size,
        &evidence,
        &evidence_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re create local attestation evidence failed. Peer" << my_ip << to_string(my_port) << ": obtain local evidence failed." << oe_result_str(result) << endl;
        return "-1";
    }
    // sp[0] message type; sp[1]: ip; sp[2]: port; sp[3] evidence; sp[4] pem_key
    string message = uint8_to_hex_string(evidence, evidence_size) + "," + uint8_to_hex_string(pem_key, pem_key_size);
    if (PRINT_ATTESTATION_MESSAGES)
    {
        cout << "[+]Local Re create local attestation evidence. Peer (" << my_ip << ":" << to_string(my_port) << ") generate local evidence size:" << evidence_size << ", pem_key_size: " << pem_key_size << endl;
    }
    // free(evidence);
    evidence = NULL;
    // free(pem_key);
    pem_key = NULL;
    // free(format_settings);
    format_settings = NULL;
    // free(format_id);
    format_id = NULL;
    return message;
}

bool process_client_channel_setup(vector<std::string> sp, oe_enclave_t *attester_enclaves)
{
    int ret;
    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    std::vector<uint8_t> rsa_encrypt_data_vec = hex_string_to_uint8_vec(sp[3]);
    size_t rsa_encrypt_data_size = rsa_encrypt_data_vec.size();
    uint8_t *rsa_encrypt_data = &rsa_encrypt_data_vec[0];
    std::vector<uint8_t> mrenclave_vec = hex_string_to_uint8_vec(sp[4]);
    size_t mrenclave_size = mrenclave_vec.size();
    uint8_t *mrenclave = &mrenclave_vec[0];
    oe_result_t result = OE_OK;
    size_t uuid = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);
    if (mrenclave_size != 32)
    {
        cout << "[-]Local Re process client channel failed.mrenclave size error.It should be 32 bytes!! " << mrenclave_size << endl;
        return false;
    }
    result = rsa_decrypt_client_aes(
        attester_enclaves,
        &ret,
        rsa_encrypt_data,
        rsa_encrypt_data_size,
        mrenclave,
        mrenclave_size,
        uuid);
    // free(rsa_encrypt_data);
    rsa_encrypt_data = NULL;
    // free(mrenclave);
    mrenclave = NULL;
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process client channel failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to decrypt aes-reply from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return false;
    }
    else
    {
        cout << "[+]Local Re process client channel.Peer (" << my_ip << ":" << to_string(my_port) << ") success to decrypt aes-reply from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return true;
    }
}

bool process_client_request(vector<std::string> sp,
                            oe_enclave_t *attester_enclaves,
                            uint8_t **reply_data, size_t *reply_data_size,
                            size_t *reply_type)
{
    bool pr = true;
    int ret;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    std::vector<uint8_t> encrypt_data_vec = hex_string_to_uint8_vec(sp[3]);
    size_t encrypt_data_size = encrypt_data_vec.size();
    uint8_t *encrypt_data = &encrypt_data_vec[0];
    std::vector<uint8_t> mrenclave_vec = hex_string_to_uint8_vec(sp[4]);
    size_t mrenclave_size = mrenclave_vec.size();
    uint8_t *mrenclave = &mrenclave_vec[0];
    oe_result_t result = OE_OK;
    size_t client_id = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);
    if (mrenclave_size != 32)
    {
        cout << "[-]Local Re process process_client_request failed.mrenclave size error.It should be 32 bytes!! " << mrenclave_size << endl;
        return false;
    }
    result = aes_decrypt_client_messages(
        attester_enclaves,
        &ret,
        encrypt_data,
        encrypt_data_size,
        mrenclave,
        mrenclave_size,
        reply_data,
        reply_data_size,
        client_id,
        reply_type);
    // free(mrenclave);
    mrenclave = NULL;
    // free(encrypt_data);
    encrypt_data = NULL;
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process process_client_request failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to decrypt aes-reply from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return false;
    }
    else
    {
        if (PRINT_ATTESTATION_MESSAGES)
            cout << "[+]Local Re process process_client_request.Peer (" << my_ip << ":" << to_string(my_port) << ") succed to decrypt aes-reply from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return true;
    }
}
/**********************Remote Attestation*********************************/
string create_remote_attestation_evidence(oe_enclave_t *attester_enclaves)
{
    uint8_t *evidence;
    uint8_t *pem_key;
    size_t pem_key_size;
    int ret;
    size_t evidence_size;
    uint8_t *format_settings;
    size_t format_settings_size;
    oe_uuid_t *format_id = &sgx_remote_uuid;
    oe_result_t result = OE_OK;

    result = get_enclave_format_settings(
        attester_enclaves,
        &ret,
        format_id,
        &format_settings,
        &format_settings_size);

    result = get_evidence_with_public_key(
        attester_enclaves,
        &ret,
        format_id,
        nullptr,
        0,
        &pem_key,
        &pem_key_size,
        &evidence,
        &evidence_size);

    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process create_remote_attestation_evidence failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to obtain evidence for remote attestation." << endl;
        return "-1";
    }

    string evidence_string = uint8_to_hex_string(evidence, evidence_size);
    string pem_key_string = uint8_to_hex_string(pem_key, pem_key_size);
    string message = evidence_string + "," + pem_key_string;
    if (PRINT_ATTESTATION_MESSAGES)
    {
        // cout << "[+]Local Re process create_remote_attestation_evidence.Peer (" << my_ip << ":" << to_string(my_port) << ") generate remote evidence size:" << evidence_size << ", pem_key_size: " << pem_key_size << "." << endl;
    }

    format_id = NULL;
    evidence = NULL;
    pem_key = NULL;
    format_settings = NULL;

    return message;
}

// process receiving remote evidence
bool process_attestation_remote_pk_evidence(vector<std::string> sp, oe_enclave_t *attester_enclaves)
{
    uint8_t *evidence;
    uint8_t *pem_key;
    size_t pem_key_size;
    int ret;
    size_t evidence_size;
    uint8_t *format_settings;
    size_t format_settings_size;
    oe_uuid_t *format_id = &sgx_remote_uuid;
    oe_result_t result = OE_OK;
    uint8_t *encrypt_ecdsa_data;
    size_t encrypt_ecdsa_data_size;

    // sp[0]: msg type; sp[1]: ip; sp[2]: port;  sp[3]: evidence; sp[4]: pem_key ; sp[5] ecdsa test
    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    size_t uuid = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);

    // string ip_port = sp[1] + "_" + sp[2];
    // std::vector<uint8_t> ip_port_vec = hex_string_to_uint8_vec_version2(ip_port);
    std::vector<uint8_t> evidence_vec = hex_string_to_uint8_vec(sp[3]);
    evidence_size = evidence_vec.size();
    evidence = &evidence_vec[0];

    std::vector<uint8_t> pem_key_vec = hex_string_to_uint8_vec(sp[4]);
    pem_key_size = pem_key_vec.size();
    pem_key = &pem_key_vec[0];

    result = get_enclave_format_settings(
        attester_enclaves,
        &ret,
        format_id,
        &format_settings,
        &format_settings_size);

    result = verify_evidence(
        attester_enclaves,
        &ret,
        format_id,
        pem_key,
        pem_key_size,
        evidence,
        evidence_size,
        uuid);

    format_id = NULL;
    evidence = NULL;
    pem_key = NULL;
    format_settings = NULL;
    encrypt_ecdsa_data = NULL;
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process attestation remote_pk_evidence failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to attestate master (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return false;
    }
    else
    {
        return true;
    }
}

/**********************Self-defined Funtions*********************************/
string create_encrypted_aes_pk(oe_enclave_t *attester_enclaves, size_t uuid)
{
    int ret;
    oe_result_t result = OE_OK;
    uint8_t *rsa_pk;
    size_t rsa_pk_size;
    uint8_t *encrypt_data;
    size_t encrypt_data_size;
    uint8_t *rsa_sig;
    size_t rsa_sig_size;

    result = rsa_encrypt_and_sig_aes(
        attester_enclaves,
        &ret,
        &rsa_pk,
        &rsa_pk_size,
        &encrypt_data,
        &encrypt_data_size,
        &rsa_sig,
        &rsa_sig_size,
        uuid);

    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process create_encrypted_aes_pk failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to obtain ase pk for secure communication channel." << endl;
        exit(1);
        return "-1";
    }

    string rsa_pk_string = uint8_to_hex_string(rsa_pk, rsa_pk_size);
    string encrypt_data_string = uint8_to_hex_string(encrypt_data, encrypt_data_size);
    string sigature_string = uint8_to_hex_string(rsa_sig, rsa_sig_size);
    string message = rsa_pk_string + "," + encrypt_data_string + "," + sigature_string;

    if (PRINT_ATTESTATION_MESSAGES)
    {
        cout << "[+]Local Re process create_encrypted_aes_pk .Peer (" << my_ip << ":" << to_string(my_port) << ") generate ase pk for secure communication channel." << endl;
    }
    return message;
}

bool process_aes_setup_request(vector<std::string> sp, oe_enclave_t *attester_enclaves)
{
    // sp[0]: msg type; sp[1]: ip; sp[2]: port;  sp[3]: rsa_pk; sp[4]: encrypt_data ; sp[5] rsa_sig
    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    int ret;
    std::vector<uint8_t> rsa_pk_vec = hex_string_to_uint8_vec(sp[3]);
    size_t rsa_pk_size = rsa_pk_vec.size();
    uint8_t *rsa_pk = &rsa_pk_vec[0];

    std::vector<uint8_t> rsa_encrypt_data_vec = hex_string_to_uint8_vec(sp[4]);
    size_t rsa_encrypt_data_size = rsa_encrypt_data_vec.size();
    uint8_t *rsa_encrypt_data = &rsa_encrypt_data_vec[0];

    std::vector<uint8_t> rsa_sigature_vec = hex_string_to_uint8_vec(sp[5]);
    size_t rsa_sig_size = rsa_sigature_vec.size();
    uint8_t *rsa_sig = &rsa_sigature_vec[0];
    string ip_port = sp[1] + "_" + sp[2];
    oe_result_t result = OE_OK;

    result = rsa_decrypt_verify_sig_and_set_aes(
        attester_enclaves,
        &ret,
        rsa_pk,
        rsa_pk_size,
        rsa_encrypt_data,
        rsa_encrypt_data_size,
        rsa_sig,
        rsa_sig_size);
    rsa_pk = NULL;
    rsa_encrypt_data = NULL;
    rsa_sig = NULL;
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process process_aes_setup_request failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to decrypt aes-reply from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return false;
    }
    else
    {
        return true;
    }
}

string create_encrypted_ecdsa_pk(oe_enclave_t *attester_enclaves, size_t uuid)
{
    int ret;
    oe_result_t result = OE_OK;
    uint8_t *encrypt_data;
    size_t encrypt_data_size;
    result = aes_encrypt_ecdsa(
        attester_enclaves,
        &ret,
        &encrypt_data,
        &encrypt_data_size,
        uuid);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process create_encrypted_ecdsa_pk failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to obtain ecdsa pk." << endl;
        return "-1";
    }

    string encrypt_data_string = uint8_to_hex_string(encrypt_data, encrypt_data_size);
    if (PRINT_ATTESTATION_MESSAGES)
    {
        cout << "[+]Local Re process create_encrypted_ecdsa_pk.Peer (" << my_ip << ":" << to_string(my_port) << ") generate ecdsa pk." << endl;
    }
    // free(encrypt_data);
    encrypt_data = NULL;
    return encrypt_data_string;
}

bool process_edcsa_reply(vector<std::string> sp, oe_enclave_t *attester_enclaves, size_t uuid)
{
    // sp[0]: msg type; sp[1]: ip; sp[2]: port;  sp[3]: encrypt_data; sp[4]: encrypt_data_size ;
    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    int ret;
    size_t uuide = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);

    std::vector<uint8_t> encrypt_data_vec = hex_string_to_uint8_vec(sp[3]);
    size_t encrypt_data_size = encrypt_data_vec.size();
    uint8_t *encrypt_data = &encrypt_data_vec[0];
    int result;
    result = aes_decrypt_ecdsa_reply(
        attester_enclaves,
        &ret,
        encrypt_data,
        encrypt_data_size,
        uuide);

    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process process_edcsa_reply failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to decrypt ecdsa-pk from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return false;
    }
    else
    {
        return true;
    }
}

// Do for system init: peer pack all peer ecdsa key
//  Just use aes key to encrypt all ecdsa key and send to everyone
string create_ecdsa_pki_certificate(oe_enclave_t *attester_enclaves, size_t uuid)
{
    uint8_t *rsa_pk;
    size_t rsa_pk_size;
    int ret;
    oe_result_t result = OE_OK;
    uint8_t *encrypt_data;
    size_t encrypt_data_size;
    uint8_t *ecdsa_sigature;
    size_t sigature_size;

    result = create_kpi_certificate_ecall(
        attester_enclaves,
        &ret,
        &encrypt_data,
        &encrypt_data_size,
        uuid);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process create_ecdsa_pki_certificate failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to obtain pki certificate for secure communication channel." << endl;
        return "-1";
    }
    string encrypt_data_string = uint8_to_hex_string(encrypt_data, encrypt_data_size);

    if (PRINT_ATTESTATION_MESSAGES)
    {
        cout << "[+]Local Re process create_ecdsa_pki_certificate Successful .Peer (" << my_ip << ":" << to_string(my_port) << ") generate pki certificate for system initializaiton." << endl;
    }
    return encrypt_data_string;
}

bool process_ecdsa_pki_certificate(vector<std::string> sp, oe_enclave_t *attester_enclaves)
{
    // sp[0]: msg type; sp[1]: ip; sp[2]: port;  sp[3]: ecdsa_pki_certificate;  ;
    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    int ret;
    std::vector<uint8_t> encrypt_data_vec = hex_string_to_uint8_vec(sp[3]);
    size_t encrypt_data_size = encrypt_data_vec.size();
    uint8_t *encrypt_data = &encrypt_data_vec[0];
    int result;
    size_t uuid = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);

    // Send it into enclave and aes decrypt
    result = process_kpi_certificate_ecall(
        attester_enclaves,
        &ret,
        encrypt_data,
        encrypt_data_size,
        uuid);
    return true;
}

// INFO ROTE
bool process_AE_Update_Counter(vector<std::string> sp, oe_enclave_t *attester_enclaves)
{
    // sp[0]: msg type; sp[1]: ip; sp[2]: port;  sp[3]: ecdsa_pki_certificate;sp[4] AE_INDEX  ;
    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    int ret = 1;
    oe_result_t result = OE_OK;
    size_t uuid = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);
    // string message = "-1";
    std::vector<uint8_t> encrypt_data_vec = hex_string_to_uint8_vec(sp[3]);
    size_t encrypt_data_size = encrypt_data_vec.size();
    uint8_t *encrypt_data = &encrypt_data_vec[0];
    // step 1 update local AES table
    // If successful fetch ecdsa_signed and send it to peer to check
    if (encrypt_data_size > 2048)
    {
        cout << "[+]Local Re process_AE_Update_Counter failed.The size is bigger than 2048" << endl;
        exit(1);
        return false;
    }
    ae_queues aq;
    cout << "sp:" << sp[4] << " " << sp[5] << " " << endl;
    cout << "?啥问题" << sp.size() << endl;
    // memcpy(aq.encrypt_data, encrypt_data, encrypt_data_size);
    aq.encrypt_data_size = 0;
    aq.uuid = uuid;
    aq.first_connect = false;
    aq.index_time = sp[5];
    aq.timestamp = sp[5];
    aq.round = 1;
    aq.index = (uuid);             // TODO index也好像不知道干什么这一块有点混乱,这一处需要重写。
    for (size_t i = 0; i < 1; i++) //一个当50
    {
        if (PRINT_ATTESTATION_MESSAGES)
            cout << "[+]Local Re push ae requests into queue .The requests id is " << sp[5] << " Time is " << ser->print_time() << endl;
        ser->ae_queues_vector.push_back(aq);
    }

    return true;
}

// INFO ROTE
bool process_AE_Read(vector<std::string> sp, oe_enclave_t *attester_enclaves)
{
    // sp[0]: msg type; sp[1]: ip; sp[2]: port;  sp[3]: ecdsa_pki_certificate;sp[4] AE_INDEX  ;
    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    int ret = 1;
    oe_result_t result = OE_OK;
    size_t uuid = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);
    // string message = "-1";
    std::vector<uint8_t> encrypt_data_vec = hex_string_to_uint8_vec(sp[3]);
    size_t encrypt_data_size = encrypt_data_vec.size();
    uint8_t *encrypt_data = &encrypt_data_vec[0];
    // step 1 update local AES table
    // If successful fetch ecdsa_signed and send it to peer to check
    if (encrypt_data_size > 2048)
    {
        cout << "[+]Local Re process_AE_Update_Counter failed.The size is bigger than 2048" << endl;
        exit(1);
        return false;
    }
    ae_queues aq;
    memcpy(aq.encrypt_data, encrypt_data, encrypt_data_size);
    aq.encrypt_data_size = encrypt_data_size;
    aq.uuid = uuid;
    aq.first_connect = false;
    aq.index_time = sp[5];
    aq.timestamp = sp[6];
    aq.round = 1;
    aq.index = stoi(sp[5]);
    for (size_t i = 0; i < 1; i++)
    {
        if (PRINT_ATTESTATION_MESSAGES)
            cout << "[+]Local Re push ae requests into queue .The requests id is " << sp[5] << " Time is " << ser->print_time() << endl;

        ser->ae_queues_vector.push_back(aq); //一个当50
    }

    return true;
}

string process_AE_Update_Echo(vector<std::string> sp, oe_enclave_t *attester_enclaves)
{
    // sp[0]: msg type; sp[1]: ip; sp[2]: port;  sp[3]: encrypt_data_string; sp[4]: ecdsa_sigature_string ;
    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    int ret;
    std::vector<uint8_t> encrypt_data_vec = hex_string_to_uint8_vec(sp[3]);
    size_t encrypt_data_size = encrypt_data_vec.size();
    uint8_t *encrypt_data = &encrypt_data_vec[0];
    uint8_t *encrypt_data2;
    std::vector<uint8_t> ecdsa_sigature_vec = hex_string_to_uint8_vec(sp[4]);
    size_t uuid = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);
    string message = "-1";
    oe_result_t result = OE_OK;
    // pipline
    Re_piplines rq;
    memcpy(rq.encrypt_data, encrypt_data, encrypt_data_size);
    rq.encrypt_data_size = encrypt_data_size;
    rq.uuid = uuid;
    // rq.round = 2;
    rq.index = stoi(sp[5]);
    ser->Re_piplines_vector.push_back(rq);
    result = signed_with_verify(attester_enclaves, &ret, uuid, 3, nullptr, 0, encrypt_data, encrypt_data_size, 0, nullptr, 0, &encrypt_data2, &encrypt_data_size); // 4ms
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process_AE_Update_Echo failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to decrypt ecdsa-pk from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        encrypt_data = NULL;
        encrypt_data2 = NULL;
        return message;
    }
    string encrypt_data_string = uint8_to_hex_string(encrypt_data, encrypt_data_size);
    message = encrypt_data_string + ",1," + sp[5];
    if (sp.size() > 6)
    {
        cout << "sp" << sp[6] << endl;
        for (vector<Re_piplines>::iterator it = ser->Re_piplines_vector.begin(); it != ser->Re_piplines_vector.end(); ++it)
        {
            if (stoi(sp[6]) == it->index)
            {
                ser->Re_piplines_vector.erase(it);
                break;
            }
        }
    }
    // string ecdsa_sigature_string = uint8_to_hex_string(ecdsa_sigature, ecdsa_sigature_size);

    encrypt_data = NULL;
    free(encrypt_data2);
    encrypt_data2 = NULL;
    return message;
}

bool process_AE_Update_Return_Echo_verify(vector<std::string> sp, oe_enclave_t *attester_enclaves)
{
    //  sp[0]: msg type; sp[1]: ip; sp[2]: port;  sp[3]: encrypt_data_string; sp[4]: ecdsa_sigature_string ;
    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    int ret;
    std::vector<uint8_t> encrypt_data_vec = hex_string_to_uint8_vec(sp[3]);
    size_t encrypt_data_size = encrypt_data_vec.size();
    uint8_t *encrypt_data = &encrypt_data_vec[0];
    std::vector<uint8_t> ecdsa_sigature_vec = hex_string_to_uint8_vec(sp[4]);
    size_t ecdsa_sigature_size = ecdsa_sigature_vec.size();
    uint8_t *ecdsa_sigature = &ecdsa_sigature_vec[0];
    size_t uuid = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);
    string message = "-1";
    oe_result_t result = OE_OK;
    // Verify message
    result = verify(attester_enclaves, &ret, uuid, 0, ecdsa_sigature, ecdsa_sigature_size, encrypt_data, encrypt_data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process_AE_Update_Return_Echo_verify failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to decrypt ecdsa-pk from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return false;
    }

    return true;
}

string process_AE_Update_Return_Echo_genc_message(oe_enclave_t *attester_enclaves, int RE_uuid, string uuid)
{
    int ret;
    size_t encrypt_data_size;
    uint8_t *encrypt_data;
    // size_t ecdsa_sigature_size;
    // uint8_t *ecdsa_sigature;
    string message = "-1";
    oe_result_t result = OE_OK;
    int indexre = stoi(uuid);
    ae_infos temp_info;
    temp_info.index = indexre;
    temp_info.echo_time = ser->print_time();
    ser->ae_infos_vector.push_back(temp_info);
    for (vector<Re_piplines>::iterator it = ser->Re_piplines_vector.begin(); it != ser->Re_piplines_vector.end(); ++it)
    {
        if (indexre == it->index && it->round == 1)
        {
            it->round = 1;
            break;
        }
    }

    result = ecdsa_signed(attester_enclaves, &ret, RE_uuid, 1, nullptr, 0,
                          &encrypt_data, &encrypt_data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process_AE_Update_Return_Echo_genc_message failed. Re main return echo step 2 ecdsa signed is failed" << endl;
        return message;
    }
    if (PRINT_ATTESTATION_MESSAGES)
        cout << "[+process_AE_Update] Local Re Process Batch.Finish `ecdsa_signed` enclave function. This requests index is " << ser->print_time() << " and id is " << RE_uuid << endl;
    string encrypt_data_string = uint8_to_hex_string(encrypt_data, encrypt_data_size);
    // string ecdsa_sigature_string = uint8_to_hex_string(ecdsa_sigature, ecdsa_sigature_size);
    message = encrypt_data_string + ",null," + uuid;

    return message;
}

string process_AE_Update_Final_Echo(vector<std::string> sp, oe_enclave_t *attester_enclaves)
{
    // sp[0]: msg type; sp[1]: ip; sp[2]: port;  sp[3]: encrypt_data_string; sp[4]: ecdsa_sigature_string ;

    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    int ret;
    std::vector<uint8_t> encrypt_data_vec = hex_string_to_uint8_vec(sp[3]);
    size_t encrypt_data_size = encrypt_data_vec.size();
    uint8_t *encrypt_data = &encrypt_data_vec[0];
    std::vector<uint8_t> ecdsa_sigature_vec = hex_string_to_uint8_vec(sp[4]);
    size_t ecdsa_sigature_size = ecdsa_sigature_vec.size();
    uint8_t *ecdsa_sigature = &ecdsa_sigature_vec[0];
    size_t uuid = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);
    string message = "-1";
    oe_result_t result = OE_OK;
    int indexre = stoi(sp[5]);
    bool find_index = true;

    result = verify(attester_enclaves, &ret, uuid, 1, ecdsa_sigature, ecdsa_sigature_size, encrypt_data, encrypt_data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process_AE_Update_Final_Echo failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to decrypt ecdsa-pk from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return message;
    }
    result = ecdsa_signed(attester_enclaves, &ret, uuid, 2, &ecdsa_sigature, &ecdsa_sigature_size,
                          &encrypt_data, &encrypt_data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process_AE_Update_Final_Echo failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to decrypt ecdsa-pk from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return message;
    }
    if (PRINT_ATTESTATION_MESSAGES)
        cout << "[+process_AE_Update_Final] Local Re Process Batch.Finish `ecdsa_signed` enclave function. This requests index is " << ser->print_time() << " and id is " << uuid << endl;
    string encrypt_data_string = uint8_to_hex_string(encrypt_data, encrypt_data_size);
    string ecdsa_sigature_string = uint8_to_hex_string(ecdsa_sigature, ecdsa_sigature_size);
    message = encrypt_data_string + "," + ecdsa_sigature_string + "," + sp[5];

    return message;
}

bool process_AE_Update_Final_verify(vector<std::string> sp, oe_enclave_t *attester_enclaves)
{
    // sp[0]: msg type; sp[1]: ip; sp[2]: port;  sp[3]: encrypt_data_string; sp[4]: ecdsa_sigature_string ;
    bool pr = true;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    int ret;
    std::vector<uint8_t> encrypt_data_vec = hex_string_to_uint8_vec(sp[3]);
    size_t encrypt_data_size = encrypt_data_vec.size();
    uint8_t *encrypt_data = &encrypt_data_vec[0];
    // std::vector<uint8_t> ecdsa_sigature_vec = hex_string_to_uint8_vec(sp[4]);
    // size_t ecdsa_sigature_size = ecdsa_sigature_vec.size();
    // uint8_t *ecdsa_sigature = &ecdsa_sigature_vec[0];
    size_t uuid = ser->find_uuid_by_ip_and_port(sender_ip, sender_port);
    string message = "-1";
    oe_result_t result = OE_OK;

    result = verify(attester_enclaves, &ret, uuid, 2, nullptr, 0, encrypt_data, encrypt_data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "[-]Local Re process_AE_Update_Final_verify failed.Peer (" << my_ip << ":" << to_string(my_port) << ") failed to decrypt ecdsa-pk from peer (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return false;
    }

    return true;
}