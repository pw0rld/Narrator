
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
#include <ctime>
#include <iostream>
#include <string>
#include <list>
#include <iostream>
#include <fstream>
#include <thread>
#include <chrono>
#include <vector>
#include <random>
#include "enclave_operation.h"
#include "params.h"

using namespace std;
using namespace std::chrono;

string my_ip = "badip";
uint32_t my_port;
mt19937 rng;
unsigned long time_of_start;
oe_enclave_t *cl_enclave = NULL;
bool is_system_init = false;
const int testcount = 100;

int64_t print_time()
{

    std::chrono::microseconds ms = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    return ms.count();
}
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

string create_client_message(oe_enclave_t *attester_enclaves, int message_type)
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
    result = aes_encrypt_client_messages(
        attester_enclaves,
        &ret,
        requests_message,
        sizeof(requests_message),
        &encrypt_data,
        &encrypt_data_size,
        &mrenclave_data,
        &mrenclave_data_size,
        message_type);
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

// Input parmarers: argv1  enclave path; argv2 IP port; argv3 peer config; argv4 public ip addr; argv5 private ip addr
int main(int argc, const char *argv[])
{

    // create enclave from path
    int64_t nums[testcount] = {0};
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;
    cl_enclave = create_enclave(argv[1], flags);
    std::string test_message = "";
    int64_t sum = 0;
    int seal_size;
    /*-----------------------Seal 1K Test-------------------------------------------------------------*/
    for (int i = 0; i < testcount; i++)
    {
        seal_size = 1024;
        int64_t start_time = print_time();
        test_message = create_client_message(cl_enclave, seal_size);
        int64_t end_time = print_time();
        nums[i] = end_time - start_time;
    }
    for (int i = 0; i < testcount; i++)
    {
        sum += nums[i];
    }
    cout << "Seal 10000次size " << seal_size << " 的时间和为：" << sum << "\t其平均值为：" << sum / testcount << endl;

    /**********************************Load 1K Test***************************************************************/
    nums[testcount] = {0};
    sum = 0;
    for (int i = 0; i < testcount; i++)
    {
        int ret = 1;
        int64_t start_time = print_time();
        ret = load_application_state(cl_enclave);
        int64_t end_time = print_time();
        nums[i] = end_time - start_time;
    }
    for (int i = 0; i < testcount; i++)
    {
        sum += nums[i];
    }
    cout << "Load 10000次的时间和为：" << sum << "\t其平均值为：" << sum / testcount << endl;
    printf("Host: Terminating enclaves\n");

    /*-----------------------Seal 10K Test-------------------------------------------------------------*/
    for (int i = 0; i < testcount; i++)
    {
        seal_size = 10240;
        int64_t start_time = print_time();
        test_message = create_client_message(cl_enclave, seal_size);
        int64_t end_time = print_time();
        nums[i] = end_time - start_time;
    }
    for (int i = 0; i < testcount; i++)
    {
        sum += nums[i];
    }
    cout << "Seal 10000次size " << seal_size << " 的时间和为：" << sum << "\t其平均值为：" << sum / testcount << endl;
    printf("Host: Terminating enclaves\n");

    /**********************************Load 10K Test***************************************************************/
    nums[testcount] = {0};
    sum = 0;
    for (int i = 0; i < testcount; i++)
    {
        int ret = 1;
        int64_t start_time = print_time();
        ret = load_application_state(cl_enclave);
        int64_t end_time = print_time();
        nums[i] = end_time - start_time;
    }
    for (int i = 0; i < testcount; i++)
    {
        sum += nums[i];
    }
    cout << "Load 10000次的时间和为：" << sum << "\t其平均值为：" << sum / testcount << endl;

    /*-----------------------Seal 100K Test-------------------------------------------------------------*/
    for (int i = 0; i < testcount; i++)
    {
        seal_size = 102400;
        int64_t start_time = print_time();
        test_message = create_client_message(cl_enclave, seal_size);
        int64_t end_time = print_time();
        nums[i] = end_time - start_time;
    }
    for (int i = 0; i < testcount; i++)
    {
        sum += nums[i];
    }
    cout << "Seal 10000次size " << seal_size << " 的时间和为：" << sum << "\t其平均值为：" << sum / testcount << endl;
    printf("Host: Terminating enclaves\n");

    /**********************************Load 100K Test***************************************************************/
    nums[testcount] = {0};
    sum = 0;
    for (int i = 0; i < testcount; i++)
    {
        int ret = 1;
        int64_t start_time = print_time();
        ret = load_application_state(cl_enclave);
        int64_t end_time = print_time();
        nums[i] = end_time - start_time;
    }
    for (int i = 0; i < testcount; i++)
    {
        sum += nums[i];
    }
    cout << "Load 10000次的时间和为：" << sum << "\t其平均值为：" << sum / testcount << endl;
    printf("Host: Terminating enclaves\n");

    if (cl_enclave)
        terminate_enclave(cl_enclave);
    /**********************************Load Test***************************************************************/
}
