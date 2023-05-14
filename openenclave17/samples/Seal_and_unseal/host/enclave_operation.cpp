#include "enclave_operation.h"
// using namespace std;

// cretae enclaves
oe_enclave_t *create_enclave(const char *enclave_path, uint32_t flags)
{
    oe_enclave_t *enclave = NULL;
    oe_result_t result = oe_create_attestation_enclave(
        enclave_path, OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        printf("Error: Creating enclave failed. %s", oe_result_str(result));
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

/**
 * @brief This function is seal enclave data
 * @param attester_enclave
 * @param data
 * @param data_size
 * @return int
 */
int seal_host_write(unsigned char *sealed_data, size_t sealed_data_size)
{
    int ret = 1;
    // cout << "sealed_data_size " << sealed_data_size << endl;
    fstream file;
    file.open(FILE_SEAL_STATE, ios::out | ios::binary);
    if (!file.is_open())
    {
        cout << "File open failed!" << endl;
        file.close();
        goto exit;
    }
    file.write((char *)sealed_data, sealed_data_size);
    file.close();
    // cout << "File success!" << endl;
    ret = 0;
exit:
    return ret;
}

/**
 * @brief This function is use to unseal encalve data and verify result
 * @param target_enclave The enclave target
 * @return int
 */
int load_application_state(oe_enclave_t *target_enclave)
{
    oe_result_t result;
    int ret = 1;
    unsigned char *data = NULL;
    size_t data_size = 0;
    fstream file;
    // if the file does not exist, exit
    if (access(FILE_SEAL_STATE, 0) == -1)
    {
        // printf("Cannot access sealed state. \n");
        goto exit;
    }
    file.open(FILE_SEAL_STATE, ios::in | ios::binary);
    file.seekg(0, file.end);
    data_size = file.tellg(); // obtain the file size
    file.seekg(0, file.beg);
    data = (unsigned char *)malloc(data_size + 1);
    memset(data, 0, data_size + 1);
    file.read((char *)data, data_size);
    file.close();
    result = unseal_state_data(target_enclave, &ret, data, data_size);
    if ((result != OE_OK) || (ret != 0))
    {
        cout << "Error: ecall unseal_state_data returned " << oe_result_str(result)
             << " ret = " << ret << (ret ? " (failed)" : " (success)") << endl;
        goto exit;
    }
    ret = 0;
exit:
    free(data);
    data = NULL;
    return ret;
}