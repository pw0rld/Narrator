
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
#include <stdint.h>
#include <string>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <boost/chrono.hpp>
#include <boost/thread/thread.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <openssl/sha.h>
#include "network/My_Server.hpp"
#include "configuration.h"
#include "params.h"
#include "process_ae_requests.hpp"
#include <iostream>
#include "host/enclave_operation.h"
#include "./network/message_produce.h"

using namespace std;
extern tcp_server *ser;
extern oe_enclave_t *se_enclave;
extern string my_ip;
extern uint32_t my_port;
int index_re = 0;
int ae_index_covert = 50;
int ae_index_covert_v = 0;

void process_ae_requests()
{
    bool batch_turnon = true;
    size_t vector_size = 0;
    string message = "";
    oe_result_t result = OE_OK;
    size_t vector_queue_size = 0;
    int ret = 1;
    vector<ae_queuesb> temp_queue_vector;
    uint8_t *temp_data_buffer = nullptr;
    ae_queuesb temp_queue;
    size_t temp_queue_size = 0;
    int info_index = 0;
    int control_wait = 15;
    int batch_group = 0;
    while (1)
    {
        try
        {
            batch_turnon = true;
            vector_size = ser->ae_queues_vector.size();
            message = "";
            result = OE_OK;
            vector_queue_size = (vector_size > ser->batch_size) ? ser->batch_size : vector_size;
            if (ae_index_covert == 0)
            {
                ae_index_covert = ser->batch_size;
                ae_index_covert_v++;
            }
            if (control_wait >= 0)
            {
                control_wait--;
                if (PRINT_ATTESTATION_MESSAGES)
                    cout << "[+Ae] Local Re Process Batch.This requests index is " << index_re << " AE requests id is " << ae_index_covert_v << " and now batch process vector size is " << vector_queue_size << " and batch vector size is " << ser->ae_queues_vector.size() << " Time is " << ser->print_time() << endl;
            }
            if (batch_turnon && vector_queue_size > 0)
            {
                control_wait = 15;
                ae_index_covert = ae_index_covert - vector_queue_size;
                if (PRINT_ATTESTATION_MESSAGES)
                    cout << "[+Ae] Local Re Process Batch.Into If branch. This requests index is " << ser->print_time() << " and id is " << index_re << endl;
                ret = 1;
                temp_queue_vector.clear();
                ser->ae_queues_vector_size.push_back(vector_queue_size);
                for (size_t it = 0; it < vector_queue_size; ++it)
                {
                    if (ser->ae_queues_vector.front().encrypt_data_size > 2048)
                    {
                        if (PRINT_ATTESTATION_MESSAGES)
                            cout << "[-Ae]Local Re Process Batch error.Error size is more bigger!!" << endl;
                        continue;
                    }
                    memcpy(temp_queue.encrypt_data, ser->ae_queues_vector.front().encrypt_data, ser->ae_queues_vector.front().encrypt_data_size);
                    temp_queue.encrypt_data_size = ser->ae_queues_vector.front().encrypt_data_size;
                    temp_queue.uuid = ser->ae_queues_vector.front().uuid;
                    temp_queue_vector.push_back(temp_queue);
                    ae_queues temp_test;
                    temp_test.index = ser->ae_queues_vector.front().index;
                    temp_test.uuid = ser->ae_queues_vector.front().uuid;
                    temp_test.index_time = ser->ae_queues_vector.front().index_time;
                    temp_test.timestamp = ser->ae_queues_vector.front().timestamp;

                    cout << "[+Ae] Local Re Process Batch.Process If branch. This requests index is " << ser->print_time() << " and id is " << temp_test.index << endl;
                    ser->ae_queues_vector_process.push(temp_test);
                    ser->ae_queues_vector.erase(ser->ae_queues_vector.begin());
                }
                size_t temp_queue_size = temp_queue_vector.size() * sizeof(ae_queuesb);
                temp_data_buffer = (uint8_t *)malloc(temp_queue_size + 1);
                memset(temp_data_buffer, 0, temp_queue_size + 1);
                memcpy(temp_data_buffer, &temp_queue_vector, temp_queue_size);
                int64_t new_time = ser->print_time();
                if (PRINT_ATTESTATION_MESSAGES)
                    cout << "[+Ae] Local Re Process Batch.Ready Into `updateLocalASECounterTable` enclave function. This requests index is " << ser->print_time() << " and id is " << index_re << endl;
                result = updateLocalASECounterTable(se_enclave, &ret, -1, temp_data_buffer, temp_queue_size);
                if (PRINT_ATTESTATION_MESSAGES)
                    cout << "[+Ae] Local Re Process Batch.Finish `updateLocalASECounterTable` enclave function. This requests index is " << ser->print_time() << " and id is " << index_re << endl;
                free(temp_data_buffer);
                temp_data_buffer = NULL;
                if (ret == 0)
                {
                    uint8_t *encrypt_data;
                    size_t encrypt_data_size;
                    if (PRINT_ATTESTATION_MESSAGES)
                        cout << "[+Ae] Local Re Process Batch.Ready Into `ecdsa_signed` enclave function. This requests index is " << ser->print_time() << " and id is " << index_re << endl;

                    result = ecdsa_signed(se_enclave, &ret, 2, 3, nullptr, 0, &encrypt_data, &encrypt_data_size);
                    if ((result != OE_OK) || (ret != 0))
                    {
                        cout << "[-Ae]Local Re Process Batch error.Something failed for updateLocalASECounterTable batch " << endl;
                        return;
                    }
                    if (PRINT_ATTESTATION_MESSAGES)
                        cout << "[+Ae] Local Re Process Batch.Finish ae `ecdsa_signed` enclave function. This requests index is " << ser->print_time() << " and id is " << index_re << endl;

                    string encrypt_data_string = uint8_to_hex_string(encrypt_data, encrypt_data_size);
                    message = encrypt_data_string + ",1";
                    message += "," + to_string(index_re);
                    if (PRINT_ATTESTATION_MESSAGES)
                        cout << "[+Ae] Local Re Process Batch.Ready to send peer RE. This requests index is " << ser->print_time() << " and id is " << index_re << endl;
                    for (map<int, map<string, uint32_t>>::iterator it = ser->Re_Peers.begin(); it != ser->Re_Peers.end(); ++it)
                    {
                        string sender_ip = (it->second).begin()->first;
                        size_t sender_port = (it->second).begin()->second;
                        size_t send_index = ser->find_peer_index_by_ip_and_port(sender_ip, sender_port);

                        if (send_index != -1)
                        {
                            // Re_piplines rq;
                            // bool find_index = true;
                            // memcpy(rq.encrypt_data, encrypt_data, encrypt_data_size);
                            // rq.encrypt_data_size = encrypt_data_size;
                            // rq.uuid = send_index;
                            // rq.round = 1;
                            // rq.index = index_re;
                            // ser->Re_piplines_vector.push_back(rq);
                            // for (vector<Re_piplines>::iterator it = ser->Re_piplines_vector.begin(); it != ser->Re_piplines_vector.end(); ++it)
                            // {
                            //     if (it->round == 2 && index_re - 1 == it->index)
                            //     {
                            //         it->round = 3;
                            //         message += "," + to_string(it->index);
                            //         break;
                            //     }
                            //     else if (index_re - 1 == it->index && it->round != 2)
                            //     {
                            //         break;
                            //     }
                            // }
                            ser->fetch_signed_messages(send_index, message);
                        }
                    }
                    ae_infos temp_info;
                    temp_info.index = index_re;
                    temp_info.return_time = ser->print_time();
                    ser->ae_infos_vector.push_back(temp_info);
                    free(encrypt_data);
                    encrypt_data = NULL;
                    if (PRINT_ATTESTATION_MESSAGES)
                        cout << "[+Ae] Local Re Process Batch.Finish send peer RE. This requests index is " << ser->print_time() << " and id is " << index_re << endl;
                    index_re++;
                }
            }
            else
            {
                boost::this_thread::sleep(boost::posix_time::milliseconds(5));
            }
        }
        catch (boost::thread_interrupted &)
        {
            cout << "Worry!!! " << endl;
        }
    }

    return;
}
