#ifndef ENCLAVE_OPERATION_H
#define ENCLAVE_OPERATION_H

#include <iostream>
#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/host.h>
#include "attestation_u.h"
#include "configuration.h"
#include "params.h"
#include "./network/MyServer.hpp"
#include "./network/ip_requests.h"
#include <unistd.h>

using namespace std;

oe_enclave_t *create_enclave(const char *enclave_path, uint32_t flags);
void terminate_enclave(oe_enclave_t *enclave);
int seal_host_write(size_t sealed_data_size, unsigned char *sealed_data);
int save_application_state(oe_enclave_t *attester_enclave);

#endif
