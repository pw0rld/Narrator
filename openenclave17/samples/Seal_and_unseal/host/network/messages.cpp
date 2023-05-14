#include "messages.h"
#include "misc.h"

extern string my_ip;
extern uint32_t my_port;

// using json = nlohmann::json;
extern tcp_server *ser;
// SGX Local Attestation UUID.

static oe_uuid_t sgx_local_uuid = {OE_FORMAT_UUID_SGX_LOCAL_ATTESTATION};
// SGX Remote Attestation UUID.
static oe_uuid_t sgx_remote_uuid = {OE_FORMAT_UUID_SGX_ECDSA};
oe_uuid_t *format_id = &sgx_local_uuid;

using namespace std;

bool key_present(string key, map<string, int> &passed)
{
    if (passed.find(key) != passed.end())
        return true;
    passed.insert(make_pair(key, 1));
    return false;
}

string create__ping(string tt, uint32_t dnext, unsigned long tsec, int mode)
{
    string s = "#ping," + my_ip + "," + to_string(my_port) + "," + tt + "," + to_string(dnext) + "," + to_string(tsec) + "," + to_string(mode);
    return s;
}

bool parse__ping(vector<std::string> sp, map<string, int> &passed, string &sender_ip, uint32_t &sender_port, string &tt, uint32_t &dnext, unsigned long &tsec, int &mode)
{
    if (sp.size() < 7)
        return false;
    if (key_present(sp[0] + sp[1] + sp[2], passed))
        return false;

    bool pr = true;
    sender_ip = sp[1];
    sender_port = safe_stoi(sp[2], pr);
    tt = sp[3];
    dnext = safe_stoi(sp[4], pr);
    tsec = safe_stoull(sp[5], pr);
    mode = safe_stoi(sp[6], pr);

    if (PRINT_TRANSMISSION_ERRORS && !(pr))
    {
        cout << "Could not get proper values of ping" << endl;
        cout << pr << endl;
        return false;
    }

    return true;
}

bool parse__process_msg(vector<std::string> sp, map<string, int> &passed, string &sender_ip, uint32_t &sender_port, string &msg)
{
    if (sp.size() < 10)
        return false;
    if (key_present(sp[0] + sp[1] + sp[2] + sp[3] + sp[4] + sp[5], passed))
        return false;

    bool pr = true;
    sender_ip = sp[1];
    sender_port = safe_stoi(sp[2], pr);
    msg = sp[3];
    // nb.parent         = safe_stoull(  sp[ 4], pr );
    // nb.hash           = safe_stoull(  sp[ 5], pr );

    if (PRINT_TRANSMISSION_ERRORS && !(pr && sender_ip.size() > 0))
    {
        cout << "Could not get proper values of process_block" << endl;
        // cout << pr << " " << sender_ip << " " << nb.chain_id << endl;

        for (int i = 1; i <= 5; i++)
            cout << sp[i] << endl;

        return false;
    }
    return true;
}

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
/**
 * @brief Create a attestation local format setting object
 * @param attester_enclaves
 * @return string
 */
string create_attestation_local_format_setting(oe_enclave_t *attester_enclaves)
{
    int ret = 1;
    uint8_t *format_settings = NULL;
    size_t format_settings_size = 0;
    string format_setting_string = "-1";
    oe_result_t result = OE_OK;

    result = get_enclave_format_settings(
        attester_enclaves,
        &ret,
        format_id,
        &format_settings,
        &format_settings_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf("Host: get_format_settings failed. %s\n", oe_result_str(result));
        ret = 1;
        return "-1";
    }
    format_setting_string = uint8_to_hex_string(format_settings, format_settings_size);
    // cout << "format_settings_size" << format_settings_size << endl;
    return format_setting_string;
}

bool process_attestation_local_pk_evidence(vector<std::string> sp, oe_enclave_t *attester_enclave)
{
    int ret = 1;
    oe_result_t result = OE_OK;
    std::vector<uint8_t> evidence_vec;
    std::vector<uint8_t> pk_vec;
    size_t uuid = 0;

    evidence_vec = hex_string_to_uint8_vec(sp[3]);
    pk_vec = hex_string_to_uint8_vec(sp[4]);
    result = verify_evidence(
        attester_enclave,
        &ret,
        format_id,
        &pk_vec[0],
        pk_vec.size(),
        &evidence_vec[0],
        evidence_vec.size(),
        uuid);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_evidence_and_set_public_key failed. %s\n",
            oe_result_str(result));
        ret = 1;
        return false;
    }
    return true;
}

// obtain verifier's format_setting and generate local attestation evidence
string create_aes_channel(oe_enclave_t *attester_enclaves)
{
    int ret = 1;
    uint8_t *encrypt_aes_data;
    size_t encrypt_aes_data_size;
    uint8_t *mrenclave_data;
    size_t mrenclave_data_size;
    oe_result_t result = OE_OK;
    string encrypt_aes_data_string;
    string mrenclave_string;
    string send_message;

    result = rsa_encrypt_aes_key(
        attester_enclaves,
        &ret,
        &encrypt_aes_data,
        &encrypt_aes_data_size,
        &mrenclave_data,
        &mrenclave_data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        printf(
            "Host: verify_evidence_and_set_public_key failed. %s\n",
            oe_result_str(result));
        ret = 1;
        return "-1";
    }

    encrypt_aes_data_string = uint8_to_hex_string(encrypt_aes_data, encrypt_aes_data_size);
    mrenclave_string = uint8_to_hex_string(mrenclave_data, mrenclave_data_size);
    send_message = encrypt_aes_data_string + "," + mrenclave_string;
    return send_message;
}

string create_client_message(oe_enclave_t *attester_enclaves, size_t message_type)
{
    int ret = 1;
    uint8_t *encrypt_data;
    size_t encrypt_data_size;
    uint8_t *mrenclave_data;
    size_t mrenclave_data_size;
    oe_result_t result = OE_OK;
    uint8_t requests_message[5] = "Test";
    string encrypt_aes_data_string = "";
    string mrenclave_string = "";
    string send_message = "";
    // cout << "create_client_message entry " << endl;
    result = aes_encrypt_client_messages(
        attester_enclaves,
        &ret,
        requests_message,
        sizeof(requests_message),
        &encrypt_data,
        &encrypt_data_size,
        &mrenclave_data,
        &mrenclave_data_size, message_type);
    // cout << "create_client_message end " << endl;
    if ((result != OE_OK) || (ret != 0))
    {
        printf("Error: generate clients' requests failed. %s\n", oe_result_str(result));
        ret = 1;
        exit(1);
        return "-1";
    }
    encrypt_aes_data_string = uint8_to_hex_string(encrypt_data, encrypt_data_size);
    mrenclave_string = uint8_to_hex_string(mrenclave_data, mrenclave_data_size);
    send_message = encrypt_aes_data_string + "," + mrenclave_string;
    free(mrenclave_data);
    mrenclave_data = NULL;
    free(encrypt_data);
    encrypt_data = NULL;
    return send_message;
}

bool process_server_reply(vector<std::string> sp, oe_enclave_t *attester_enclaves, size_t *is_ready)
{
    bool pr = true;
    int ret;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    std::vector<uint8_t> reply_data_vec = hex_string_to_uint8_vec(sp[3]);
    size_t reply_data_size = reply_data_vec.size();
    oe_result_t result = OE_OK;
    cout << "1111 " << endl;
    result = updateITHash(
        attester_enclaves,
        &ret,
        &reply_data_vec[0],
        reply_data_size);
    cout << "1111 " << endl;
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "Peer (" << my_ip << ":" << to_string(my_port) << ") failed to decrypt reply from SE (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        exit(1);
        return false;
    }
    return true;
}
bool process_read_requests_reply(vector<std::string> sp, oe_enclave_t *attester_enclaves, size_t *is_ready)
{
    bool pr = true;
    int ret;
    string sender_ip = sp[1];
    uint32_t sender_port = safe_stoi(sp[2], pr);
    ret = load_application_state(attester_enclaves);
    if (ret != 0)
    {
        cout << "Peer (" << my_ip << ":" << to_string(my_port) << ") failed to decrypt reply from SE (" << sender_ip << ":" << to_string(sender_port) << ")." << endl;
        return false;
    }
    return true;
}