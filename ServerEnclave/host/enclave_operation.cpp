#include "enclave_operation.h"
using namespace std;

// cretae enclaves
oe_enclave_t *create_enclave(const char *enclave_path, uint32_t flags)
{
    oe_enclave_t *enclave = NULL;
    oe_result_t result = oe_create_attestation_enclave(
        enclave_path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        printf(
            "Error: Creating enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("[+] Enclave successfully created.\n");
    }
    return enclave;
}

// terminate enclaves
void terminate_enclave(oe_enclave_t *enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: Enclave successfully terminated.\n");
}

// Ocall implement
int seal_host_write(size_t sealed_data_size, unsigned char *sealed_data)
{
    int ret = 1;
    // AE Gen_Request Index Time:
    if (PRINT_ATTESTATION_MESSAGES)
        cout << "[+]RE Seal Function. This seal file size is " << sealed_data_size << endl;

    fstream file;
    file.open(FILE_SEAL_STATE, ios::out | ios::binary);
    if (!file.is_open())
    {
        cout << "[+]RE Seal Function. File open failed!" << endl;
        file.close();
        ret = 1;
        return ret;
        ;
    }
    file.write((char *)sealed_data, sealed_data_size);
    file.close();
    if (PRINT_ATTESTATION_MESSAGES)
        cout << "[+]RE Seal Function.Seal File success!" << endl;
    ret = 0;
exit:
    return ret;
}
