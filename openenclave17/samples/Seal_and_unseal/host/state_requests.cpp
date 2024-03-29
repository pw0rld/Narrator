
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
#include "state_requests.h"
#include "network/messages.h"

using namespace std;
extern tcp_server *ser;
extern oe_enclave_t *cl_enclave;
extern string my_ip;
extern uint32_t my_port;
extern bool is_system_init;
bool isRequestPending = false;
void state_requests()
{
	// //periodically run the thread to execute system setup
	// try{
	// 	boost::this_thread::sleep(boost::posix_time::milliseconds(EXPECTED_REQUESTS_INTERVEL_IN_MILLISECONDS));
	// }
	// catch (boost::thread_interrupted){
	// 	state_requests();
	// }

	// //if the system is initialized and no pending requests, then generate state update requests
	// if(is_system_init == true && isRequestPending == false){
	// 	ser->send_client_requests(STATE_UPDATE);
	// 	isRequestPending = true;
	// 	if (PRINT_STATES_MESSAGES)
	//     {
	//         std::cout << "Peer (" << my_ip << ":" << my_port << ") send state-update request to server (" << ser->get_server_ip() << ":" << ser->get_server_port() << ")." << std::endl;
	//     }
	// }
	// state_requests();
	// return;
}
