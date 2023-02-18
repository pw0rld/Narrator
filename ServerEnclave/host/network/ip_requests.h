#ifndef IP_REQUEST_H
#define IP_REQUEST_H

#include <iostream>
#include "My_Server.hpp"
#include "../params.h"
#include <istream>
using namespace std;

bool key_present(string key, map<string, int> &passed);

string create__ping(string tt, uint32_t dnext, unsigned long tsec, int mode);

string read_other_info(oe_enclave_t *enclave);
bool parse__ping(vector<std::string> sp, map<string, int> &passed, string &sender_ip, uint32_t &sender_port, string &tt, uint32_t &dnext, unsigned long &tsec, int &mode);

bool parse__process_msg(vector<std::string> sp, map<string, int> &passed, string &sender_ip, uint32_t &sender_port, string &msg);

bool checkTendermintSetup(size_t uuid, oe_enclave_t *enclave);
std::string &replace_all(string &str, const string &old_value, const string &new_value);

int get_url_response(const std::string &url, std::string &out_response_data);

int read_and_verify_tendermint(std::string data, oe_enclave_t *enclave);
bool write_tendermint(oe_enclave_t *enclave);
bool Base64Decode(const string &input, string *output);

#endif
