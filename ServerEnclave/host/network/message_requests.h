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
#ifndef MESSAGE_REQUEST_H
#define MESSAGE_REQUEST_H

#include <iostream>
#include "MyServer.hpp"
#include "../configuration.h"
#include "../params.h"
#include "ip_requests.h"
#include "host/enclave_operation.h"

using namespace std;

string uint8_to_hex_string(const uint8_t *v, const size_t size);
vector<uint8_t> hex_string_to_uint8_vec(const string &hex);
vector<uint8_t> hex_string_to_uint8_vec_version2(const string &hex);
string uint8_to_hex_string_version2(const uint8_t *v, const size_t s);

// funtions used between SE peers
string create_remote_attestation_evidence(oe_enclave_t *attester_enclaves);
string create_encrypted_aes_pk(oe_enclave_t *attester_enclaves, size_t uuid);
string create_encrypted_ecdsa_pk(oe_enclave_t *attester_enclaves, size_t uuid);
string create_ecdsa_pki_certificate(oe_enclave_t *attester_enclaves, size_t uuid);
bool process_attestation_remote_pk_evidence(vector<std::string> sp, oe_enclave_t *attester_enclaves);
bool process_aes_setup_request(vector<std::string> sp, oe_enclave_t *attester_enclaves);
bool process_edcsa_reply(vector<std::string> sp, oe_enclave_t *attester_enclaves, size_t uuid);
bool process_ecdsa_pki_certificate(vector<std::string> sp, oe_enclave_t *attester_enclaves);

// funtions used between SE and clients
string create_attestation_local_format_setting(oe_enclave_t *attester_enclaves);
string create_local_attestation_evidence(oe_enclave_t *attester_enclaves, vector<std::string> sp);
bool process_client_channel_setup(vector<std::string> sp, oe_enclave_t *attester_enclaves);
bool process_client_request(vector<std::string> sp, oe_enclave_t *attester_enclaves, uint8_t **reply_data, size_t *reply_data_size, size_t *reply_type);

bool process_AE_Update_Counter(vector<std::string> sp, oe_enclave_t *attester_enclaves);
string process_AE_Update_Echo(vector<std::string> sp, oe_enclave_t *attester_enclaves);
bool process_AE_Update_Return_Echo_verify(vector<std::string> sp, oe_enclave_t *attester_enclaves);
string process_AE_Update_Return_Echo_genc_message(oe_enclave_t *attester_enclaves, int RE_uuid, string AE_uuid);
string process_AE_Update_Final_Echo(vector<std::string> sp, oe_enclave_t *attester_enclaves);
bool process_AE_Update_Final_verify(vector<std::string> sp, oe_enclave_t *attester_enclaves);

#endif
