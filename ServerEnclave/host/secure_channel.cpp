
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
#include "secure_channel.h"
#include "system_init.h" //TODO: remove later

using namespace std;
extern tcp_server *ser;
extern oe_enclave_t *se_enclave;
extern string my_ip;
extern uint32_t my_port;

int se_slave_count = 0;
// Just for client request 
void secure_channel()
{
	// periodically run the thread to execute system setup
	try
	{
		boost::this_thread::sleep(boost::posix_time::milliseconds(EXPECTED_ATTESTTAION_WAIT_TIME_IN_MILLISECONDS));
	}
	catch (boost::thread_interrupted &)
	{
		system_init();
	}

	bool is_system_init_finished = true;
	// iterate for each SE peer to do remote attestation
	for (uint32_t i = 0; i < ser->get_peers_size(); i++)
	{
		if((ser->get_peer_role(i).compare("se_slave") == 0)){
			if (ser->is_peer_connected(i) == false)
			{ // if peer is not connected, check the next one
				is_system_init_finished = false;
				continue;
			}
			else if ((ser->get_peer_role(i)).compare("client") == 0)
			{
				continue;
			}
			uint8_t init_state = ser->get_peer_attest_state(i); // obtain peers' state
			cout << "peer index: " << to_string(i) << " State:" << to_string(init_state) << endl;
			switch (init_state)
			{
			// do mutual remote attestation
			case SYSTEM_INIT_START:
			{
				if (ser->get_peer_wait_count(i) > 0)
				{
					ser->decrease_peer_wait_count(i);
				}
				else
				{
					ser->send_remote_attestation_to_peer(i);
					ser->set_peer_wait_count(i);
					// print the state of sending RA request
					if (PRINT_ATTESTATION_MESSAGES)
					{
						cout << "Peer (" << my_ip << ":" << my_port << ") send remote attestation to peer (" << ser->get_peer_ip(i) << ":" << ser->get_peer_port(i) << ")." << std::endl;
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
						cout << "Peer (" << my_ip << ":" << my_port << ") send AES setup to peer (" << ser->get_peer_ip(i) << ":" << ser->get_peer_port(i) << ")." << std::endl;
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
						cout << "Peer (" << my_ip << ":" << my_port << ") ask ecdsa pub key from peer (" << ser->get_peer_ip(i) << ":" << ser->get_peer_port(i) << ")." << std::endl;
					}
				}
				break;
			}
			// send PKI certificate
			case SYSTEM_INIT_PKI_SETUP:
			{
				if (ser->isPKISetup() == false)
					break;
				if (ser->get_peer_wait_count(i) > 0)
				{
					ser->decrease_peer_wait_count(i);
				}
				else
				{
					if (PRINT_ATTESTATION_MESSAGES)
					{
						cout << "Peer (" << my_ip << ":" << my_port << ") send pki-certificate to peer (" << ser->get_peer_ip(i) << ":" << ser->get_peer_port(i) << ")." << std::endl;
					}

					ser->broadcast_ecdsa_pki_to_peers(i);
					ser->set_peer_wait_count(i);
					// print the state of sending RA request
				}
				break;
			}
			// upload initialization info to chain to prevent forking
			case SYSTEM_INIT_UPDATE_CHAIN:
			{
				// TODO: interact with blockchain
				break;
			}
			// complete the init process
			case SYSTEM_INIT_DONE:
			{
				// TODO: interact with blockchain
				break;
			}
			default:
			{
				if (PRINT_WARNNING_MESSAGES)
				{
					cout << "Peer (" << my_ip << ":" << my_port << ") init process: unknown state." << endl;
				}
				break;
			}
			}

			// check whether the init process completes
			if (init_state != SYSTEM_INIT_DONE)
			{
				is_system_init_finished = false;
			}
		}
	}

	if (is_system_init_finished == true)
	{
		if (PRINT_ATTESTATION_MESSAGES)
		{
			cout << "Master (" << my_ip << ":" << my_port << ") finish PKI Setup." << std::endl;
			ser->print_peers();
			cout << "SeverEnclave End time " << ser->print_time() << endl;
		}
	}
	else
	{
		system_init();
	}
	return;
}
