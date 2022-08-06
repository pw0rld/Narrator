
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
#include "network/MyServer.hpp"
#include "network/ip_requests.h"
#include "configuration.h"
#include "params.h"
#include "system_init.h"
#include "process_ae_requests.hpp"

using namespace std;
extern tcp_server *ser;
extern oe_enclave_t *se_enclave;
extern string my_ip;
extern uint32_t my_port;
boost::thread *mythread2;

void system_init()
{
	while (1)
	{
		try
		{
			boost::this_thread::sleep(boost::posix_time::milliseconds(1));
		}
		catch (boost::thread_interrupted &)
		{
			boost::this_thread::sleep(boost::posix_time::milliseconds(1));
		}

		bool is_system_init_finished = false;
		bool ready_setup_pki = true;
		bool self_tendermint_flag = true;
		int check_tendermint_counter = 0;
		// iterate for each SE peer to do remote attestation
		for (uint32_t i = 0; i < ser->get_peers_size(); i++)
		{
			uint8_t init_state = ser->get_peer_attest_state(i); // obtain peers' state

			if (PRINT_ATTESTATION_MESSAGES)
			{
				// cout << "[+]Local Re check peer status.Peer index: " << to_string(i) << " State:" << to_string(init_state) << " Port: " << ser->get_peer_port(i) << " uuid is " << ser->get_peer_uuid(i) << " and connected " << ser->is_peer_connected(i) << " is_system_init_finished " << is_system_init_finished << endl;
			}

			if (ser->is_peer_connected(i) == false && (ser->get_peer_role(i)).compare("se_slave") == 0)
			{									 // if peer is not connected, check the next one+
				is_system_init_finished = false; // make sure all peer finish system init
				continue;
			}

			switch (init_state)
			{
			// do mutual remote attestation
			case SYSTEM_INIT_START:
			{
				if (ser->get_peer_wait_count(i) > 0)
				{
					ser->decrease_peer_wait_count(i);
					// boost::this_thread::sleep(boost::posix_time::milliseconds(1000));
				}
				else
				{
					ser->send_remote_attestation_to_peer(i); //发送一次之后需要等待
					ser->set_peer_wait_count(i);
					if (PRINT_ATTESTATION_MESSAGES)
					{
						cout << "[+]Local Re over `SYSTEM_INIT_START`.Peer (" << my_ip << ":" << my_port << ") send remote attestation to peer (" << ser->get_peer_ip(i) << ":" << ser->get_peer_port(i) << ")." << std::endl;
					}
				}
				break;
			}
			// generate AES key for secure communication
			case SYSTEM_INIT_SECURE_CHANNEL:
			{
				if (ser->get_peer_wait_count(i) > 0)
				{
					ser->decrease_peer_wait_count(i);
				}
				else
				{
					ser->setup_secure_channel_to_peer(i);
					ser->set_peer_wait_count(i);
					// print the state of sending RA request
					if (PRINT_ATTESTATION_MESSAGES)
					{
						cout << "[+]Local Re over `SYSTEM_INIT_SECURE_CHANNEL`. Peer (" << my_ip << ":" << my_port << ") send AES setup to peer (" << ser->get_peer_ip(i) << ":" << ser->get_peer_port(i) << ")." << std::endl;
					}
				}
				break;
			}
			// Ask for ECDSA pk for PKI certificate
			case SYSTEM_INIT_EXCHANGE_PK:
			{
				if (ser->get_peer_wait_count(i) > 0)
				{
					ser->decrease_peer_wait_count(i);
				}
				else
				{
					ser->request_ecdsa_pk_from_peer(i);
					ser->set_peer_wait_count(i);
					// print the state of sending RA request
					if (PRINT_ATTESTATION_MESSAGES)
					{
						cout << "[+]Local Re over `SYSTEM_INIT_EXCHANGE_PK`.Peer (" << my_ip << ":" << my_port << ") ask ecdsa pub key from peer (" << ser->get_peer_ip(i) << ":" << ser->get_peer_port(i) << ")." << std::endl;
					}
				}
				break;
			}
			// send PKI certificate must all peer setup its ecdsa PKI
			// make sure all peer send its PKI key to master peer
			case SYSTEM_INIT_PKI_SETUP:
			{
				if (ser->isPKISetup()) // make sure all peer send its PKI key to master peer
				{
					if (self_tendermint_flag)
					{
						std::cout << "Now enter the blockchain setp" << std::endl;
						string tendermint_data = read_other_info(se_enclave);
						int is_tru = read_and_verify_tendermint(tendermint_data, se_enclave);
						if (is_tru == 0)
						{
							cout << "[+]Check tendermint record is not exist " << endl;
							bool is_write = write_tendermint(se_enclave);
							if (is_write)
							{
								cout << "[+]Record  is successful" << endl;
							}
						}
						else
						{
							cout << "Recorde message into chain failed! " << endl;
							exit(1);
						}
					}
					else
					{
						std::cout << "Master upload its record into tendermint. Now is waitting other peer. " << std::endl;
					}
				}
				else
				{
					std::cout << "Master send pki failed. " << std::endl;
					break;
				}
			}
			// upload initialization info to chain to prevent forking
			case SYSTEM_INIT_UPDATE_CHAIN:
			{
				// This setp will check tendermint chain that is exists the peer record or not exists
				// Master will cycle check
				if (checkTendermintSetup(ser->get_peer_uuid(i), se_enclave) == true) // make sure all peer send its PKI key to master peer
				{
					check_tendermint_counter++;
				}
				else
				{
					cout << "checkTendermintSetup failed!!!!" << endl;
					exit(1);
				}
			}
			// complete the init process
			case SYSTEM_INIT_DONE:
			{
				// The setp is the finally setp, in this step will check tendermint record.
				if (check_tendermint_counter == ser->Re_Peers.size())
				{
					cout << "SYSTEM_INIT_DONE Finish" << endl;
					is_system_init_finished = true;
					check_tendermint_counter = 0;
					break;
				}
			}
			default:
			{
				if (PRINT_WARNNING_MESSAGES)
				{
					cout << "[+]Local Re over `default`.Peer (" << my_ip << ":" << my_port << ") init process: unknown state." << endl;
				}
				break;
			}
			}
		}

		if (is_system_init_finished)
		{
			cout << "[+]Local Re entry process_ae_requests step " << endl;
			ser->ae_queues_vector.reserve(sizeof(ae_queues) * 5000);
			ser->ae_infos_vector.reserve(sizeof(ae_infos) * 10);
			boost::thread t1(process_ae_requests);
			mythread2 = &t1;
			if (PRINT_ATTESTATION_MESSAGES)
			{
				cout << "[+]Master (" << my_ip << ":" << my_port << ") finish PKI Setup." << std::endl;
				ser->print_peers();
			}
			break;
		}
	}
	return;
}
