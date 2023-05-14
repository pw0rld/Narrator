// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef OE_SAMPLES_ATTESTATION_COMMON_LOG_H
#define OE_SAMPLES_ATTESTATION_COMMON_LOG_H

#include <stdio.h>

extern const char *enclave_name;

#define TRACE_ENCLAVE(fmt, ...)     \
                                    \
    printf(                         \
        "%s: ***%s(%d): " fmt "\n", \
        enclave_name,               \
        __FILE__,                   \
        __LINE__,                   \
        ##__VA_ARGS__)
#define POLICY_UNIQUE 1
#define POLICY_PRODUCT 2

#define MAX_OPTIONAL_MESSAGE_SIZE 128
#define IV_SIZE 16
#define SIGNATURE_LEN 32

// errors shared by host and enclaves
#define ERROR_SIGNATURE_VERIFY_FAIL 1
#define ERROR_OUT_OF_MEMORY 2
#define ERROR_GET_SEALKEY 3
#define ERROR_SIGN_SEALED_DATA_FAIL 4
#define ERROR_CIPHER_ERROR 5
#define ERROR_UNSEALED_DATA_FAIL 6
#define ERROR_SEALED_DATA_FAIL 7
#define ERROR_INVALID_PARAMETER 8
typedef struct _sealed_data_t
{
    unsigned char optional_message[MAX_OPTIONAL_MESSAGE_SIZE];
    size_t sealed_blob_size;
} sealed_data_t;

#endif // OE_SAMPLES_ATTESTATION_COMMON_LOG_H
