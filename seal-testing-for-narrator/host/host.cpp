// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <common/shared.h>
#include <limits.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <chrono>
#include <sys/stat.h>
#include <sys/types.h>

#include <iostream>
#include <vector>
#include "datasealing_u.h"

using namespace std;
using namespace std::chrono;

#define GET_POLICY_NAME(policy) \
    ((policy == POLICY_UNIQUE) ? "POLICY_UNIQUE" : "POLICY_PRODUCT")

const char *g_plain_text = "test plaintext";
const char *g_opt_msg = "optional sealing message";

oe_enclave_t *create_enclave(const char *enclavePath)
{
    oe_enclave_t *enclave = NULL;

    // printf("Host: Loading enclave library %s\n", enclavePath);
    oe_result_t result = oe_create_datasealing_enclave(
        enclavePath,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_datasealing_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        // printf("Host: Enclave created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t *enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: enclave terminated.\n");
}

int unseal_data_and_verify_result(
    oe_enclave_t *target_enclave,
    sealed_data_t *sealed_data,
    size_t sealed_data_size,
    unsigned char *target_data,
    size_t target_data_size)
{
    oe_result_t result;
    int ret;
    unsigned char *data = NULL;
    size_t data_size = 0;

    // cout << "Host: enter unseal_data_and_verify_result " << endl;

    result = unseal_data(
        target_enclave, &ret, sealed_data, sealed_data_size, &data, &data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "Host: ecall unseal_data returned " << oe_result_str(result)
             << " ret = " << ret << (ret ? " (failed)" : " (success)") << endl;
        ret = ERROR_SIGNATURE_VERIFY_FAIL;
        goto exit;
    }

    // print unsealed data
    // cout << "Host: Unsealed result:" << endl;
    // printf("data=%s\n", data);

    // printf("data_size=%zd\n", data_size);
    // printf("target_data_size=%zd\n", target_data_size);

    // if (strncmp(
    //         (const char *)data, (const char *)target_data, target_data_size) != 0)
    // {
    //     cout << "Host: Unsealed data is not equal to the original data."
    //          << endl;
    //     ret = ERROR_UNSEALED_DATA_FAIL;
    //     goto exit;
    // }
exit:
    if (data)
        free(data);

    // cout << "Host: exit unseal_data_and_verify_result with " << ret << endl;
    return ret;
}

int64_t test()
{

    std::chrono::microseconds ms = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    return ms.count();
}

string rand_str(int len)
{
    string str;
    char c;
    int idx;
    for (int i = 0; i < len; i++)
    {
        c = 'a' + rand() % 26;
        str.push_back(c);
    }
    return str;
}

oe_result_t seal_unseal_by_policy(
    int policy,
    oe_enclave_t *enclave_a_v1,
    oe_enclave_t *enclave_a_v2,
    oe_enclave_t *enclave_b)
{
    oe_result_t result = OE_OK;
    unsigned char *data = NULL;
    size_t data_size = 0;
    sealed_data_t *sealed_data = NULL;
    size_t sealed_data_size = 0;
    int ret = 0;
    string message = rand_str(1024);
    data = (unsigned char *)message.c_str();
    data_size = message.size() + 1;
    int64_t start_time = test();
    result = seal_data(
        enclave_a_v1,
        &ret,
        policy,
        (unsigned char *)g_opt_msg,
        strlen(g_opt_msg),
        data,
        data_size,
        &sealed_data,
        &sealed_data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "Host: seal_data failed with " << oe_result_str(result)
             << " ret = " << ret << endl;
        goto exit;
    }
    cout << "Seal size " << data_size << " start Start time " << test() - start_time << endl;

    // Unseal data in the same enclave it was sealed
    start_time = test();
    ret = unseal_data_and_verify_result(
        enclave_a_v1,
        sealed_data,
        sealed_data_size,
        (unsigned char *)g_plain_text,
        data_size);
    if (ret != 0)
    {
        cout << "Host: Validation of unsealed data failed with ret = " << ret
             << endl;
        goto exit;
    }
    cout << "UnSeal size " << data_size << " start Start time " << test() - start_time << endl;

    message = rand_str(10240);
    data = (unsigned char *)message.c_str();
    data_size = message.size() + 1;

    start_time = test();
    result = seal_data(
        enclave_a_v1,
        &ret,
        policy,
        (unsigned char *)g_opt_msg,
        strlen(g_opt_msg),
        data,
        data_size,
        &sealed_data,
        &sealed_data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "Host: seal_data failed with " << oe_result_str(result)
             << " ret = " << ret << endl;
        goto exit;
    }
    cout << "Seal size " << data_size << " start Start time " << test() - start_time << endl;

    // Unseal data in the same enclave it was sealed
    start_time = test();
    ret = unseal_data_and_verify_result(
        enclave_a_v1,
        sealed_data,
        sealed_data_size,
        (unsigned char *)g_plain_text,
        data_size);
    if (ret != 0)
    {
        cout << "Host: Validation of unsealed data failed with ret = " << ret
             << endl;
        goto exit;
    }
    cout << "UnSeal size " << data_size << " start Start time " << test() - start_time << endl;

    message = rand_str(102400);
    data = (unsigned char *)message.c_str();
    data_size = message.size() + 1;

    start_time = test();
    result = seal_data(
        enclave_a_v1,
        &ret,
        policy,
        (unsigned char *)g_opt_msg,
        strlen(g_opt_msg),
        data,
        data_size,
        &sealed_data,
        &sealed_data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "Host: seal_data failed with " << oe_result_str(result)
             << " ret = " << ret << endl;
        goto exit;
    }
    cout << "Seal size " << data_size << " start Start time " << test() - start_time << endl;

    // Unseal data in the same enclave it was sealed
    start_time = test();
    ret = unseal_data_and_verify_result(
        enclave_a_v1,
        sealed_data,
        sealed_data_size,
        (unsigned char *)g_plain_text,
        data_size);
    if (ret != 0)
    {
        cout << "Host: Validation of unsealed data failed with ret = " << ret
             << endl;
        goto exit;
    }
    cout << "UnSeal size " << data_size << " start Start time " << test() - start_time << endl;

    ret = 0;
    result = OE_OK;

exit:

    // Free host memory allocated by the enclave.
    if (sealed_data != NULL)
        free(sealed_data);

    if (ret != 0)
        result = OE_FAILURE;

    return result;
}

int main(int argc, const char *argv[])
{
    oe_result_t result = OE_OK;
    oe_enclave_t *enclave_a_v1 = NULL;
    oe_enclave_t *enclave_a_v2 = NULL;
    oe_enclave_t *enclave_b = NULL;
    int ret = 1;

    // cout << "Host: enter main" << endl;
    if (argc != 4)
    {
        cout << "Usage: " << argv[0] << " enclave1  enclave2 enclave3" << endl;
        goto exit;
    }

    // Instantiate three different enclaves from two different products
    // Product A:  enclave_a_v1 and enclave_a_v2
    // Product B:  enclave_b
    // Note: All enclaves from the same product were signed by the same
    // cerificate authority, that is, signed with the same private.pem file in
    // this sample
    enclave_a_v1 = create_enclave(argv[1]);
    if (enclave_a_v1 == NULL)
    {
        goto exit;
    }

    enclave_a_v2 = create_enclave(argv[2]);
    if (enclave_a_v2 == NULL)
    {
        goto exit;
    }

    enclave_b = create_enclave(argv[3]);
    if (enclave_a_v2 == NULL)
    {
        goto exit;
    }

    //  POLICY_UNIQUE policy
    // cout << "------------------------------------------------\n";
    // cout << "Host: Sealing data with POLICY_UNIQUE policy\n";
    // cout << "------------------------------------------------\n";
    result = seal_unseal_by_policy(
        POLICY_UNIQUE, enclave_a_v1, enclave_a_v2, enclave_b);
    if (result != OE_OK)
    {
        cout << "Host: Data sealing with POLICY_UNIQUE failed!" << ret << endl;
        goto exit;
    }

    //  POLICY_PRODUCT policy
    // cout << "------------------------------------------------\n";
    // cout << "Host: Sealing data with POLICY_PRODUCT policy\n";
    // cout << "------------------------------------------------\n";
    result = seal_unseal_by_policy(
        POLICY_PRODUCT, enclave_a_v1, enclave_a_v2, enclave_b);
    if (result != OE_OK)
    {
        cout << "Host: Data sealing with POLICY_UNIQUE failed!" << ret << endl;
        goto exit;
    }
    ret = 0;

exit:
    cout << "Host: Terminating enclaves" << endl;
    if (enclave_a_v1)
        terminate_enclave(enclave_a_v1);

    if (enclave_a_v2)
        terminate_enclave(enclave_a_v2);

    if (enclave_b)
        terminate_enclave(enclave_b);

    if (ret == 0)
        cout << "Host: Sample completed successfully." << endl;

    return ret;
}
