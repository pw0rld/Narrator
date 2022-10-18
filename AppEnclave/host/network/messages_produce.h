#ifndef MESSAGES_H
#define MESSAGES_H

#include <iostream>
#include "My_Server.hpp"
#include "../params.h"
#include "host/enclave_operation.h"

using namespace std;


#define STATE_INIT  1
#define STATE_FETCH 2
#define STATE_UPDATE  3

bool key_present(string key, map<string, int> &passed);
string create__ping(string tt, uint32_t dnext, unsigned long tsec, int mode);
bool parse__ping(vector<std::string> sp, map<string, int> &passed, string &sender_ip, uint32_t &sender_port, string &tt, uint32_t &dnext, unsigned long &tsec, int &mode);
bool parse__process_msg( vector<std::string> sp, map<string,int> &passed, string &sender_ip, uint32_t &sender_port, string &msg );

std::string uint8_to_hex_string(const uint8_t *v, const size_t size);
std::vector<uint8_t> hex_string_to_uint8_vec(const string &hex);
std::vector<uint8_t> hex_string_to_uint8_vec_version2(const string &hex);
std::string uint8_to_hex_string_version2(const uint8_t *v, const size_t s);
string create_attestation_local_format_setting(oe_enclave_t *attester_enclaves);
bool process_attestation_local_pk_evidence(vector<std::string> sp, oe_enclave_t *attester_enclaves);
string create_aes_channel(oe_enclave_t *attester_enclaves);
string create_client_message(oe_enclave_t *attester_enclaves, size_t message_type);
bool process_server_reply(vector<std::string> sp, oe_enclave_t *attester_enclaves, size_t* is_ready);

#endif
