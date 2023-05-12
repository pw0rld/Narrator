
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
#include "params.h"
#include "system_init.h"
#include "enclave_operation.h"
#include "network/messages.h"

using namespace std;
extern tcp_server *ser;
extern oe_enclave_t *cl_enclave;
extern string my_ip;
extern uint32_t my_port;
extern bool established_token;
size_t system_state = 0;
size_t wait_count = 0;
extern bool is_system_init;
void system_init()
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

	if (ser->is_server_connected() && established_token)
	{
		switch (system_state)
		{
		// generate local attestation challenge
		case SYSTEM_ATTESTATION:
		{
			if (wait_count > 0)
			{
				wait_count--;
			}
			else
			{
				ser->send_attestation_challenge();
				wait_count = MESSAGE_WAIT_COUNT;
				if (PRINT_ATTESTATION_MESSAGES)
				{
					std::cout << "Client (" << my_ip << ":" << my_port << ") send challenge to SE (" << ser->get_server_ip() << ":" << ser->get_server_port() << ")." << std::endl;
				}
			}
			break;
		}
		// generate AES key for secure communication
		case SYSTEM_INIT_SECURE_CHANNEL:
		{
			if (wait_count > 0)
			{
				wait_count--;
			}
			else
			{
				ser->setup_secure_channel_to_server();
				wait_count = MESSAGE_WAIT_COUNT;
				if (PRINT_ATTESTATION_MESSAGES)
				{
					std::cout << "Client (" << my_ip << ":" << my_port << ") send channel setup to SE (" << ser->get_server_ip() << ":" << ser->get_server_port() << ")." << std::endl;
				}
			}
			break;
		}
		// request to init states at SE
		case SYSTEM_LOAD_STATE:
		{
			// TODO load status
			// ser->send_client_requests(STATE_FETCH);
			if (/*load_application_state(cl_enclave) ==*/1)
			{
				system_state = SYSTEM_INIT_STATE;
				if (PRINT_ATTESTATION_MESSAGES)
				{
					std::cout << "Client (" << my_ip << ":" << my_port << ") cannot access privious states." << std::endl;
				}
			}
			else
			{
				system_state = SYSTEM_GET_STATE;
				if (PRINT_ATTESTATION_MESSAGES)
				{
					std::cout << "Client (" << my_ip << ":" << my_port << ") successfully obtain sealed data." << std::endl;
				}
			}
			break;
		}
		// request to init states at SE if not setup
		case SYSTEM_INIT_STATE:
		{
			if (ser->ak)
			{
				ser->start_times = ser->print_time2();
				ser->ak = false;
			}
			if (PRINT_ATTESTATION_MESSAGES)
			{
				std::cout << "Peer (" << my_ip << ":" << my_port << ") obtain latest states from server (" << ser->get_server_ip() << ":" << ser->get_server_port() << ")." << std::endl;
			}
			// return;
			system_state = SYSTEM_INIT_DONE;
			break;
		}
		// request the latest state
		case SYSTEM_GET_STATE:
		{
			if (wait_count > 0)
			{
				wait_count--;
			}
			else
			{
			}
			break;
		}
		case SYSTEM_INIT_DONE:
		{
			is_system_init = true;
			if (PRINT_ATTESTATION_MESSAGES)
			{
				cout << "Client (" << my_ip << ":" << to_string(my_port) << ") complete system setup." << endl;
			}
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
	}
	// check whether the init process completes
	if (system_state != SYSTEM_INIT_DONE)
	{
		system_init();
	}
	else
	{
		cout << "开始发送！" << endl;
		// string msg = create_client_message(cl_enclave, STATE_FETCH);
		ser->send_read_requests(STATE_FETCH);
		// ser->send_client_requests(STATE_FETCH);
		return;
	}
	return;
}
