#ifndef ENCLAVE_OPERATION_H
#define ENCLAVE_OPERATION_H

#include <openenclave/attestation/sgx/evidence.h>
#include <openenclave/host.h>
#include "attestation_u.h"
#include "params.h"
#include <iostream>
#include <fstream>
#include <map>
#include <iomanip>
#include <sstream>
#include <unistd.h>

using namespace std;
#define GET_POLICY_NAME(policy) ((policy == POLICY_UNIQUE) ? "POLICY_UNIQUE" : "POLICY_PRODUCT")


oe_enclave_t* create_enclave(const char* enclave_path, uint32_t flags);
void terminate_enclave(oe_enclave_t* enclave);
int seal_host_write(size_t sealed_data_size,unsigned char * sealed_data);
int load_application_state(oe_enclave_t *target_enclave);

#endif
